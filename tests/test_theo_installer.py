"""Installer primitives use only temporary fixture files, never actual profiles or editors."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("theo_installer_test", ROOT / "packaging/installer/install.py")
builder = load("theo_builder_test", ROOT / "scripts/build_theo_release.py")


@pytest.fixture
def fixture_home(tmp_path, monkeypatch):
    home = tmp_path / "account"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    return home


def test_subprocess_probe_separates_machine_output_from_warnings(tmp_path):
    command = [sys.executable, "-I", "-B", "-c",
               "import sys; print('1.136.0'); print('dependency warning', file=sys.stderr)"]
    assert installer.run(command, tmp_path, "Version probe", timeout=10).strip() == "1.136.0"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_subprocess_probe_bounds_both_output_streams(tmp_path, stream):
    command = [sys.executable, "-I", "-B", "-c",
               f"import sys; sys.{stream}.write('x' * 1000001)"]
    with pytest.raises(installer.InstallProblem, match="output bound"):
        installer.run(command, tmp_path, "Bounded probe", timeout=10)


def test_prefix_claim_never_reuses_unowned_or_broad_directories(tmp_path, fixture_home):
    project = tmp_path / "existing-project-fixture"
    project.mkdir()
    for prefix in (fixture_home, project, project / "runtime", Path("/")):
        with pytest.raises(installer.InstallProblem):
            installer.claim(prefix, project)
    prefix = fixture_home / "unowned"
    prefix.mkdir(mode=0o700)
    (prefix / "do-not-touch").write_text("unrelated")
    with pytest.raises(installer.InstallProblem, match="unrelated"):
        installer.claim(prefix, project)
    assert (prefix / "do-not-touch").read_text() == "unrelated"


def test_owned_prefix_and_locks_can_resume_after_failure(tmp_path, fixture_home):
    project = tmp_path / "fixture"
    project.mkdir()
    prefix = fixture_home / "runtime"
    installer.claim(prefix, project)
    original = (prefix / "owner.json").read_bytes()
    installer.claim(prefix, project)
    assert (prefix / "owner.json").read_bytes() == original
    with installer.installation_lock(prefix):
        with pytest.raises(installer.InstallProblem, match="Another Theo"):
            with installer.installation_lock(prefix):
                pass
    with installer.installation_lock(prefix):
        pass


def test_private_destinations_and_sources_refuse_symlinks(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(installer.InstallProblem, match="symlink"):
        installer.private_dir(link / "new")
    assert list(target.iterdir()) == []


def test_corrupt_artifact_is_rejected_before_use(tmp_path):
    artifact = tmp_path / "archive"
    artifact.write_bytes(b"original")
    specification = {"bytes": 8, "sha256": hashlib.sha256(b"original").hexdigest()}
    installer.verify(artifact, specification)
    artifact.write_bytes(b"modified")
    with pytest.raises(installer.InstallProblem, match="SHA256"):
        installer.verify(artifact, specification)


@pytest.mark.parametrize("member", ["../escape", "/absolute", "app/../../escape", "wrong/file"])
def test_payload_traversal_is_preflighted_before_any_file_write(tmp_path, member):
    archive = tmp_path / "payload.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        good = tarfile.TarInfo("app/requirements.txt")
        good.size = 2
        handle.addfile(good, io.BytesIO(b"ok"))
        bad = tarfile.TarInfo(member)
        bad.size = 2
        handle.addfile(bad, io.BytesIO(b"no"))
    target = tmp_path / "extract"
    with pytest.raises(installer.InstallProblem, match="unsafe"):
        installer.extract_payload(archive, target)
    assert not (target / "app").exists()


def test_payload_symlinks_and_duplicate_members_are_refused(tmp_path):
    for variant in ("symlink", "duplicate"):
        archive = tmp_path / f"{variant}.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            item = tarfile.TarInfo("app/wheels/escape.whl")
            if variant == "symlink":
                item.type, item.linkname = tarfile.SYMTYPE, "/etc/passwd"
                handle.addfile(item)
            else:
                handle.addfile(item)
                handle.addfile(item)
        with pytest.raises(installer.InstallProblem):
            installer.extract_payload(archive, tmp_path / variant)


def test_path_changes_are_owned_private_backed_up_and_mode_preserving(fixture_home):
    prefix = fixture_home / "managed"
    prefix.mkdir(mode=0o700)
    profile = fixture_home / ".zprofile"
    original = b"# user settings\nexport USER_CHOICE=kept\n"
    profile.write_bytes(original)
    profile.chmod(0o640)
    assert installer.managed_path(prefix) == "configured_for_new_shells"
    after = profile.read_bytes()
    assert after.startswith(original) and stat.S_IMODE(profile.stat().st_mode) == 0o640
    receipt = json.loads((prefix / "path-receipt.json").read_text())
    backup = Path(receipt["backup"])
    assert backup.read_bytes() == original and backup.stat().st_mode & 0o777 == 0o600
    assert installer.managed_path(prefix) == "unchanged"
    assert profile.read_bytes() == after
    profile.write_bytes(after.replace(b"owner:", b"user-edited-owner:"))
    with pytest.raises(installer.InstallProblem, match="edited"):
        installer.managed_path(prefix)


def test_path_setup_never_replaces_another_prefix_or_symlinked_profile(fixture_home):
    first, second = fixture_home / "first", fixture_home / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    installer.managed_path(first)
    profile = fixture_home / ".zprofile"
    original = profile.read_bytes()
    with pytest.raises(installer.InstallProblem):
        installer.managed_path(second)
    assert profile.read_bytes() == original
    profile.unlink()
    other = fixture_home / "other"
    other.write_text("unrelated")
    profile.symlink_to(other)
    with pytest.raises(installer.InstallProblem):
        installer.managed_path(first)
    assert other.read_text() == "unrelated"


def test_launcher_refuses_unowned_commands_and_reruns_without_global_activation(tmp_path):
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)
    root = prefix / "releases" / installer.RELEASE_ID
    root.mkdir(parents=True)
    launcher = installer.activate_launcher(prefix, root)
    assert "-I -B -m polaris.onboarding" in launcher.read_text()
    assert "-I -B -m polaris " in (prefix / "bin" / "polaris").read_text()
    assert not (prefix / "bin" / "python").exists() and not (prefix / "bin" / "uv").exists()
    installer.activate_launcher(prefix, root)
    launcher.write_text("# unrelated command\n")
    with pytest.raises(installer.InstallProblem, match="unrelated"):
        installer.activate_launcher(prefix, root)
    assert launcher.read_text() == "# unrelated command\n"


def test_environment_has_no_credentials_or_python_injection_but_keeps_safe_host_hints(tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("POLARIS_API_KEY", "synthetic-secret")
    monkeypatch.setenv("PYTHONPATH", "/untrusted-project")
    monkeypatch.setenv("BROWSER", "/untrusted-project/command")
    monkeypatch.setenv("CURSOR_SESSION_ID", "opaque-original-must-not-propagate")
    monkeypatch.setenv("TERM_PROGRAM", "vscode")
    environment = installer.clean_environment(root, user_home=True)
    assert "POLARIS_API_KEY" not in environment and "PYTHONPATH" not in environment and "BROWSER" not in environment
    assert environment["CURSOR_SESSION_ID"] == "detected"
    assert environment["TERM_PROGRAM"] == "vscode"
    assert environment["UV_OFFLINE"] == "1" and environment["UV_PYTHON_DOWNLOADS"] == "never"


@pytest.mark.parametrize("legacy", [
    ["--project", "/private/project"], ["--host", "vscode"], ["--local"],
    ["--api-url", "https://api.example"],
])
def test_installer_rejects_project_setup_arguments_before_writes(legacy, monkeypatch, capsys):
    monkeypatch.setattr(installer, "claim", lambda *a: pytest.fail("created an installation prefix"))
    args = ["--bootstrap-root", "/private/bootstrap", "--manifest-sha256", "0" * 64,
            "--release-dir", "/private/local-release", "--json", *legacy]
    assert installer.main(args) == 2
    assert "Invalid installer arguments" in json.loads(capsys.readouterr().out)["message"]


@pytest.mark.parametrize("compatibility", [[], ["--install-only"]])
def test_projectless_install_never_invokes_setup_reads_credentials_or_changes_project_profile(
    tmp_path, fixture_home, monkeypatch, capsys, compatibility,
):
    project = tmp_path / "project"
    project.mkdir()
    (project / "untouched.txt").write_text("keep")
    profile = fixture_home / ".zprofile"
    profile.write_text("# keep this profile\n")
    prefix = fixture_home / "managed"
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    manifest = {"format": "polaris.theo-bundle/1", "id": installer.RELEASE_ID,
                "version": installer.VERSION, "platform": "macos-arm64",
                "minimumMacOS": installer.MINIMUM_MACOS}
    raw = json.dumps(manifest).encode()
    (bootstrap / "manifest.json").write_bytes(raw)
    monkeypatch.setattr(installer.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(installer.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(installer.platform, "mac_ver", lambda: ("15.0", ("", "", ""), "arm64"))
    monkeypatch.setattr(installer.sys, "version_info", (3, 11, 16))
    monkeypatch.setattr(installer, "install_runtime", lambda *a, **kw: prefix / "releases" / installer.RELEASE_ID)
    monkeypatch.setattr(installer.subprocess, "call", lambda *a, **kw: pytest.fail("invoked project setup"))
    monkeypatch.setattr(installer, "managed_path", lambda *a: pytest.fail("modified the profile"))
    monkeypatch.setattr("polaris.remote.load_credentials", lambda: pytest.fail("read credentials"))
    monkeypatch.chdir(fixture_home)
    args = ["--bootstrap-root", str(bootstrap), "--manifest-sha256", hashlib.sha256(raw).hexdigest(),
            "--release-dir", str(bootstrap), "--prefix", str(prefix), "--json", *compatibility]
    assert installer.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "installed_not_configured" and report["host_verified"] is False
    assert report["activation"]["status"] == report["configuration"] == "not_requested"
    assert report["path"] == "not_requested" and set(report["commands"]) == {"theo", "polaris"}
    assert [p.name for p in project.iterdir()] == ["untouched.txt"]
    assert (project / "untouched.txt").read_text() == "keep"
    assert profile.read_text() == "# keep this profile\n"


def test_both_commands_are_preflighted_before_either_is_activated(tmp_path):
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)
    folder = prefix / "bin"
    folder.mkdir(mode=0o700)
    (folder / "polaris").write_text("unrelated")
    with pytest.raises(installer.InstallProblem, match="unrelated"):
        installer.activate_launcher(prefix, prefix / "releases" / installer.RELEASE_ID)
    assert not (folder / "theo").exists()
    assert (folder / "polaris").read_text() == "unrelated"
    assert not (prefix / "current.json").exists()


def test_legacy_launcher_metadata_can_migrate_without_executing_old_code(tmp_path):
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)
    folder = prefix / "bin"
    folder.mkdir(mode=0o700)
    previous = prefix / "releases" / "theo-0.3.0-macos-arm64-r1"
    previous.mkdir(parents=True)
    (previous / "keep").write_text("old release fixture, not executable")
    launcher = folder / "theo"
    installer.write(launcher, b"# legacy fixture, not executable code\n", mode=0o700)
    installer.json_write(prefix / "current.json", {
        "format": "polaris.theo-current/1", "release": previous.name,
        "launcher_sha256": installer.sha256(launcher),
    })
    installer.activate_launcher(prefix, prefix / "releases" / installer.RELEASE_ID)
    assert set(json.loads((prefix / "current.json").read_text())["launchers"]) == {"theo", "polaris"}
    assert (previous / "keep").read_text() == "old release fixture, not executable"


@pytest.mark.parametrize("change", ["mode", "receipt", "polaris"])
def test_activation_preserves_changed_modes_receipts_or_second_command(tmp_path, change):
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)
    root = prefix / "releases" / installer.RELEASE_ID
    installer.activate_launcher(prefix, root)
    if change == "mode":
        (prefix / "bin" / "theo").chmod(0o755)
    elif change == "receipt":
        installer.write(prefix / "current.json", b"[]")
    else:
        (prefix / "bin" / "polaris").write_text("user edited")
    before = {path: path.read_bytes() for path in (prefix / "bin").iterdir()}
    with pytest.raises(installer.InstallProblem):
        installer.activate_launcher(prefix, root)
    assert {path: path.read_bytes() for path in (prefix / "bin").iterdir()} == before


def test_interruption_quarantines_only_the_owned_component(tmp_path):
    root = tmp_path / "release"
    component = root / "app"
    component.mkdir(parents=True)
    (component / "partial").write_text("preserved")
    unrelated = root / "unrelated"
    unrelated.write_text("untouched")
    installer.quarantine(root, "app")
    assert not component.exists()
    matches = list(root.glob(".interrupted-app-*"))
    assert len(matches) == 1 and (matches[0] / "partial").read_text() == "preserved"
    assert unrelated.read_text() == "untouched"


def test_runtime_inventory_detects_tampering_and_escaping_links(tmp_path):
    root = tmp_path / "release"
    for name in ("python", "uv", "app", "analyzer"):
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "binary").write_bytes(b"trusted-fixture")
    (root / "app" / "python").symlink_to(root / "python" / "binary")
    before = installer.inventory(root)
    (root / "app" / "binary").write_bytes(b"tampered")
    assert installer.inventory(root) != before
    (root / "uv" / "escape").symlink_to(Path("/etc/passwd"))
    with pytest.raises(installer.InstallProblem, match="escapes"):
        installer.inventory(root)


def test_uv_environment_lock_is_sealed_without_weakening_inventory(tmp_path):
    root = tmp_path / "release"
    for name in ("python", "uv", "app", "analyzer"):
        (root / name).mkdir(parents=True)
    lock = root / "app" / ".lock"
    lock.write_bytes(b"")
    lock.chmod(0o666)
    with pytest.raises(installer.InstallProblem, match="permissions"):
        installer.inventory(root)
    installer.seal_environment_lock(lock)
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert installer.inventory(root)["app/.lock"]["mode"] == 0o600
    installer.seal_environment_lock(lock)
    assert lock.read_bytes() == b""


@pytest.mark.parametrize("variant", ["symlink", "hardlink", "nonempty"])
def test_environment_lock_sealing_refuses_unrelated_content(tmp_path, variant):
    lock = tmp_path / ".lock"
    other = tmp_path / "unrelated"
    other.write_bytes(b"")
    other.chmod(0o640)
    if variant == "symlink":
        lock.symlink_to(other)
    elif variant == "hardlink":
        lock.hardlink_to(other)
    else:
        lock.write_bytes(b"unrelated content")
        lock.chmod(0o640)
    with pytest.raises(installer.InstallProblem):
        installer.seal_environment_lock(lock)
    assert stat.S_IMODE(other.stat().st_mode) == 0o640
    if variant == "nonempty":
        assert lock.read_bytes() == b"unrelated content"
        assert stat.S_IMODE(lock.stat().st_mode) == 0o640


def test_completed_installation_is_verified_before_running_any_existing_binary(tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir()
    for name in ("python", "uv", "app", "analyzer"):
        (root / name).mkdir()
    (root / "installed-files.json").write_text("{}")
    (root / "app" / "unexpected-code.py").write_text("raise RuntimeError")
    monkeypatch.setattr(installer, "run", lambda *a, **kw: pytest.fail("executed a modified runtime"))
    with pytest.raises(installer.InstallProblem, match="differ"):
        installer.validate(root, {}, complete=True)


def make_wheel(path, *, name="example", version="1.0", tag="py3-none-any", extra=None):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n")
        archive.writestr(f"{name}-{version}.dist-info/WHEEL", f"Wheel-Version: 1.0\nTag: {tag}\n")
        archive.writestr(f"{name}/__init__.py", "")
        if extra:
            archive.writestr(extra, "not executable test data")


def test_release_builder_uses_outer_metadata_not_vendored_distributions(tmp_path):
    wheel = tmp_path / "example-1.0-py3-none-any.whl"
    make_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "example/_vendor/dependency-9.0.dist-info/METADATA",
            "Metadata-Version: 2.3\nName: dependency\nVersion: 9.0\n",
        )
        archive.writestr(
            "example/_vendor/dependency-9.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nTag: cp312-cp312-manylinux_2_17_aarch64\n",
        )
    assert builder.wheel_metadata(wheel) == ("example", "1.0")


@pytest.mark.parametrize("variant", ["second-distribution", "mismatched-directories"])
def test_release_builder_still_refuses_ambiguous_outer_metadata(tmp_path, variant):
    wheel = tmp_path / "example-1.0-py3-none-any.whl"
    if variant == "second-distribution":
        make_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "another-1.0.dist-info/METADATA",
            "Metadata-Version: 2.3\nName: another\nVersion: 1.0\n",
        )
        archive.writestr("example-1.0.dist-info/WHEEL" if variant == "mismatched-directories"
                         else "another-1.0.dist-info/WHEEL",
                         "Wheel-Version: 1.0\nTag: py3-none-any\n")
    with pytest.raises(ValueError, match="unambiguous"):
        builder.wheel_metadata(wheel)


@pytest.mark.parametrize("tag", ["cp312-cp312-macosx_14_0_arm64", "cp311-cp311-manylinux_2_17_aarch64", "cp311-cp311-macosx_11_0_x86_64"])
def test_release_builder_refuses_unsupported_wheels(tmp_path, tag):
    wheel = tmp_path / "example-1.0-py3-none-any.whl"
    make_wheel(wheel, tag=tag)
    with pytest.raises(ValueError, match="not compatible"):
        builder.wheel_metadata(wheel)


def test_release_builder_refuses_unpinned_duplicate_or_traversing_wheels(tmp_path):
    make_wheel(tmp_path / "example-1.0-py3-none-any.whl")
    with pytest.raises(ValueError, match="constraint"):
        builder.wheel_set(tmp_path, {"example": "2.0"})
    make_wheel(tmp_path / "example-copy.whl")
    with pytest.raises(ValueError, match="duplicate"):
        builder.wheel_set(tmp_path, {"example": "1.0"})
    bad = tmp_path / "bad.whl"
    make_wheel(bad, extra="../outside.py")
    with pytest.raises(ValueError, match="unsafe"):
        builder.wheel_metadata(bad)


def test_candidate_payload_is_hash_locked_binary_only_and_deterministic(tmp_path):
    wheel_dir = tmp_path / "wheelhouse"
    wheel_dir.mkdir()
    wheel = wheel_dir / "example-1.0-py3-none-any.whl"
    make_wheel(wheel)
    stage = tmp_path / "stage"
    builder.payload_file(stage, "app", [wheel])
    lock = (stage / "app" / "requirements.txt").read_text()
    assert lock == f"example==1.0 --hash=sha256:{builder.digest(wheel)}\n"
    first, second = tmp_path / "first.tar.gz", tmp_path / "second.tar.gz"
    builder.deterministic_archive(stage, first)
    builder.deterministic_archive(stage, second)
    assert first.read_bytes() == second.read_bytes()


def test_bootstrap_template_cannot_execute_without_rendered_pins_and_ignores_curlrc():
    template = (ROOT / "packaging/installer/install-theo.sh.in").read_text()
    assert '[[ "$MANIFEST_SHA256" =~ ^[a-f0-9]{64}$ ]]' in template
    assert "/usr/bin/curl -q " in template
    assert 'stage=$(cd "$stage" && /bin/pwd -P)' in template
    assert 'TMPDIR="$stage"' in template
    assert 'original+=("--project" "$project")' not in template
    assert "theo setup --local" in template
    assert "--add-path" in template and "Shell profiles are unchanged unless --add-path" in template
    assert "POLARIS_API_KEY=" not in template and "brew " not in template and "sudo " not in template
    assert '--require-hashes' in (ROOT / "packaging/installer/install.py").read_text()
    installer_source = (ROOT / "packaging/installer/install.py").read_text()
    assert '"--no-build"' in installer_source
    assert '"--only-binary"' not in installer_source


def test_runtime_pins_are_real_versioned_sources_not_latest_scripts():
    pins = json.loads((ROOT / "packaging/installer/runtime-pins.json").read_text())
    for name in ("python", "uv"):
        pin = pins[name]
        assert pin["url"].startswith("https://github.com/astral-sh/")
        assert "/latest/" not in pin["url"] and len(pin["sha256"]) == 64 and pin["bytes"] > 1_000_000
    assert pins["python"]["version"].startswith("3.11.")


@pytest.mark.parametrize("version", ["15.0", "15.0.0", "15.7.2", "26.6"])
def test_macos_floor_accepts_supported_versions(version):
    installer.check_macos_version(version)


@pytest.mark.parametrize("version", [
    "", "14.9", "14.9.99", "11.0", "15", "15.0beta", "15.0\n", "15.0.0.1",
    "015.0", "15.00", "-15.0", "1000.0", "15.0;true",
])
def test_macos_floor_fails_closed_before_prefix_or_native_execution(version, monkeypatch, capsys):
    monkeypatch.setattr(installer.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(installer.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(installer.platform, "mac_ver", lambda: (version, ("", "", ""), "arm64"))
    monkeypatch.setattr(installer.sys, "version_info", (3, 11, 16))
    monkeypatch.setattr(installer, "claim", lambda *a: pytest.fail("claimed a prefix"))
    monkeypatch.setattr(installer, "run", lambda *a, **kw: pytest.fail("ran a native process"))
    args = ["--bootstrap-root", "/private/nonexistent-fixture", "--manifest-sha256", "0" * 64,
            "--release-dir", "/private/nonexistent-fixture", "--json"]
    assert installer.main(args) == 2
    assert "macOS" in json.loads(capsys.readouterr().out)["message"]


def test_compliance_material_is_data_only_hash_pinned_and_in_the_sealed_inventory(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    archive = source / "compliance.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        entry = tarfile.TarInfo("compliance/THIRD_PARTY_NOTICES.txt")
        entry.size = 7
        handle.addfile(entry, io.BytesIO(b"notices"))
    expected = {"name": archive.name, "bytes": archive.stat().st_size,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    root = tmp_path / "release"
    root.mkdir(mode=0o700)
    for component in ("python", "uv", "app", "analyzer"):
        (root / component).mkdir(mode=0o700)
    copied = installer.fetch_release_artifact(root, archive.name, expected, base_url=None, release_dir=source)
    installer.extract_payload(copied, root, roots=("compliance",), max_members=30_000)
    before = installer.inventory(root)
    (root / "compliance/THIRD_PARTY_NOTICES.txt").write_bytes(b"changed")
    assert installer.inventory(root) != before
    with pytest.raises(installer.InstallProblem):
        installer.fetch_release_artifact(root, "../outside", expected, base_url=None, release_dir=source)


def test_shell_os_check_precedes_downloads_extraction_and_native_execution():
    template = (ROOT / "packaging/installer/install-theo.sh.in").read_text()
    floor = template.index('macos_version=$(/usr/bin/sw_vers -productVersion)')
    assert floor < template.index('/usr/bin/mktemp')
    assert floor < template.index('/usr/bin/curl')
    assert floor < template.index('/usr/bin/tar')
    assert floor < template.index('"$stage/python/bin/python3.11"')
    assert '[ "${BASH_REMATCH[1]}" -ge 15 ]' in template

"""Offline packaging fixtures only: never install Homebrew or execute fixture runtimes."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("homebrew_builder_test", ROOT / "scripts/build_homebrew_formula.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def tar_bytes(path, entries):
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            item = tarfile.TarInfo(name)
            if isinstance(content, tuple):
                item.type, item.linkname = content
                archive.addfile(item)
            else:
                item.size = len(content)
                item.mode = 0o755 if "/bin/" in name or name.endswith("/uv") else 0o644
                archive.addfile(item, io.BytesIO(content))


def wheel_bytes(name, version, *, package=None, tag="py3-none-any", extra_files=None):
    result = io.BytesIO()
    directory = f"{name.replace('-', '_')}-{version}.dist-info"
    files = {
        f"{directory}/METADATA": f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n".encode(),
        f"{directory}/WHEEL": f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n".encode(),
        **(extra_files or {}),
    }
    if package:
        files.update({f"polaris/{path}": content for path, content in package.items()})
        files[f"{directory}/entry_points.txt"] = (
            b"[console_scripts]\npolaris = polaris.cli:main\ntheo = polaris.onboarding.cli:main\n"
        )
    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    for path, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        writer.writerow((path, "sha256=" + digest, len(content)))
    writer.writerow((f"{directory}/RECORD", "", ""))
    files[f"{directory}/RECORD"] = rows.getvalue().encode()
    with zipfile.ZipFile(result, "w") as wheel:
        for path, content in files.items():
            wheel.writestr(path, content)
    return result.getvalue()


def seal_bundle(bundle, manifest):
    (bundle / "manifest.json").write_bytes(builder.json_bytes(manifest))
    manifest_pin = builder.artifact(bundle / "manifest.json")
    (bundle / "install-theo.sh").write_text(
        "# Non-executable fixture; no installer is ever run.\n"
        f"MANIFEST_SHA256='{manifest_pin['sha256']}'\n",
    )
    release = {
        "format": "polaris.onboarding-release/1", "id": manifest["id"], "version": manifest["version"],
        "platform": manifest["platform"], "availability": "unpublished", "downloadOrigin": None,
        "minimumMacOS": manifest["minimumMacOS"],
        "apiOrigin": None, "bootstrap": builder.artifact(bundle / "install-theo.sh"),
    }
    (bundle / "bootstrap.json").write_bytes(builder.json_bytes(release))

def synthetic_analyzer_contract(root, payload, package):
    """Synthetic, inert wheels have their own contract; production pins are never changed."""
    from polaris.review.analyzers import identity

    inspector = builder.helper("qualify_analyzer_dependencies")
    contract = identity.contract()
    contract["packages"] = {}
    for name, content in payload.items():
        inspected = inspector.inspect_bytes(content)
        directory = inspected["metadataDirectory"]
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            native = {member: item for member, item in inspected["members"].items()
                      if archive.read(member)[:4] == bytes.fromhex("cffaedfe")}
        remaining = [[member, item["sha256"], item["bytes"]]
                     for member, item in sorted(inspected["members"].items())
                     if member not in native and member != directory + "/RECORD"]
        contract["packages"][inspected["name"]] = {
            **{key: inspected[key] for key in ("sha256", "bytes", "version", "metadataDirectory")},
            "filename": name.rsplit("/", 1)[-1],
            "metadataSha256": inspected["members"][directory + "/METADATA"]["sha256"],
            "wheelMetadataSha256": inspected["members"][directory + "/WHEEL"]["sha256"],
            "nativeMembers": native,
            "unchangedMembersSha256": hashlib.sha256(json.dumps(remaining, separators=(",", ":")).encode()).hexdigest(),
        }
    raw = builder.json_bytes(contract)
    source = (ROOT / "src/polaris/review/analyzers/identity.py").read_text()
    source = source.replace(identity.CONTRACT_SHA256, hashlib.sha256(raw).hexdigest())
    source = source.replace(identity.DERIVATIVE_SHA256, contract["packages"]["semgrep"]["sha256"])
    for name, content in (("identity.py", source.encode()), ("analyzer-contract.json", raw)):
        relative = "review/analyzers/" + name
        target = root / "src/polaris" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        package[relative] = content


def synthetic_source_archive(root, bundle, artifact_hash):
    from test_source_provenance import packet_input

    inputs, specification = packet_input(root)
    specification["subjects"][0]["artifactSha256"] = artifact_hash
    helper = builder.helper("source_delivery")
    report = helper.qualifier().build_source_packet(inputs, specification, root / "third-party-sources")
    return helper.build_archive(root / "third-party-sources", report["manifestSha256"],
                                bundle / helper.ARCHIVE_NAME)


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    # All pins are real digests of tiny synthetic bytes; no production checksum is replaced.
    root = tmp_path.resolve() / "builder-source"
    (root / "scripts").mkdir(parents=True)
    (root / "packaging/installer").mkdir(parents=True)
    (root / "packaging/homebrew").mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/build_public_wheel.py", root / "scripts/build_public_wheel.py")
    for name in ("analyzer_delivery", "qualify_analyzer_dependencies", "source_delivery", "qualify_source_provenance"):
        shutil.copyfile(ROOT / "scripts" / f"{name}.py", root / "scripts" / f"{name}.py")
    shutil.copyfile(ROOT / "packaging/homebrew/polaris.rb", root / "packaging/homebrew/polaris.rb")
    monkeypatch.setattr(builder, "ROOT", root)
    package = {name: f"# Source fixture: {name}\n".encode() for name in builder.public_builder().REQUIRED}
    package["__init__.py"] = b'__version__ = "0.3.3"\n'
    package["__main__.py"] = b"# Fixture only.\n"
    package["py.typed"] = b""
    bundle = tmp_path.resolve() / builder.RELEASE_ID
    bundle.mkdir()
    pins = {}
    for component, archive_root, binary in (
        ("python", "python", "bin/python3.11"), ("uv", "uv-aarch64-apple-darwin", "uv"),
    ):
        path = bundle / f"{component}-fixture.tar.gz"
        # Only valid header data, not a runnable fixture program.
        native = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
        native += struct.pack("<6I", 0x32, 24, 1, 0x000F0000, 0x000F0500, 0)
        entries = {f"{archive_root}/{binary}": native}
        if component == "python":
            entries[f"{archive_root}/bin/python3"] = (tarfile.SYMTYPE, "python3.11")
        tar_bytes(path, entries)
        pins[component] = {**builder.artifact(path), "version": "3.11.16" if component == "python" else "0.12.20"}
    (root / "packaging/installer/runtime-pins.json").write_bytes(builder.json_bytes(pins))
    inventories = {
        "app": {"theovex-polaris": "0.3.3", "mcp": "2.2.0", "tomlkit": "0.13.3"},
        "analyzer": {"semgrep": "1.178.0+theovex.1", "setuptools": "83.0.0", "mcp": "1.29.0", "pyjwt": "2.15.0"},
    }
    payload = {}
    for name, version in inventories["analyzer"].items():
        native = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6, 1, 24, 0, 0)
        native += struct.pack("<6I", 0x32, 24, 1, 0x000F0000, 0x000F0500, 0)
        payload[f"analyzer/wheels/{name}-{version}-py3-none-any.whl"] = wheel_bytes(
            name, version, extra_files={"semgrep/core": native} if name == "semgrep" else None,
        )
    synthetic_analyzer_contract(root, payload, package)
    delivery = builder.helper("analyzer_delivery")
    for component, packages in inventories.items():
        requirements = []
        for name, version in packages.items():
            path = f"{component}/wheels/{name}-{version}-py3-none-any.whl"
            if component == "app":
                payload[path] = wheel_bytes(name, version, package=package if name == "theovex-polaris" else None)
            requirements.append(delivery.requirements_line(
                name, version, hashlib.sha256(payload[path]).hexdigest(), component=component,
            ))
        payload[f"{component}/requirements.txt"] = ("\n".join(sorted(requirements)) + "\n").encode()
    tar_bytes(bundle / "payload.tar.gz", payload)
    manifest = {
        "format": "polaris.theo-bundle/1", "id": builder.RELEASE_ID, "version": builder.VERSION,
        "platform": builder.PLATFORM, "availability": "unpublished", "downloadOrigin": None, "apiOrigin": None,
        "minimumMacOS": builder.MINIMUM_MACOS,
        "modelIncluded": False, "nativeHostVerified": False,
        "runtimes": pins, "payload": builder.artifact(bundle / "payload.tar.gz"), "environments": inventories,
        "analyzerIdentity": delivery.identity().manifest_identity(),
    }
    manifest["thirdPartySources"] = synthetic_source_archive(
        root, bundle, manifest["analyzerIdentity"]["derivativeWheelSha256"],
    )
    manifest["nativeCompatibility"] = builder.native_inventory(bundle, manifest)
    seal_bundle(bundle, manifest)
    source = tmp_path.resolve() / "theovex_polaris-0.3.3.tar.gz"
    source_files = {f"theovex_polaris-0.3.3/src/polaris/{name}": content for name, content in package.items()}
    source_files["theovex_polaris-0.3.3/pyproject.toml"] = (
        b'[project]\nname = "theovex-polaris"\nversion = "0.3.3"\n'
    )
    source_files.update({f"theovex_polaris-0.3.3/{name}": b"Public fixture.\n"
                         for name in ("README.md", "LICENSE", "NOTICE")})
    tar_bytes(source, source_files)
    return {"bundle_dir": bundle, "source_archive": source}, manifest, source_files, payload


def generate(candidate, output, **kwargs):
    inputs, *_ = candidate
    return builder.build(**inputs, output=output.resolve(), **kwargs)


def test_local_distribution_has_real_pins_separate_wheelhouses_and_no_installed_venvs(candidate, tmp_path):
    output = tmp_path / "local"
    result = generate(candidate, output, local_file=True)
    archive = output / result["artifact"]["name"]
    assert result["artifact"]["url"] == archive.as_uri()
    assert result["artifact"]["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert result["artifact"]["bytes"] == archive.stat().st_size
    assert result["availability"] == "unpublished" and result["downloadOrigin"] is None
    assert result["publicationPerformed"] is result["installationValidated"] is False
    formula = (output / "polaris.rb").read_text()
    assert f'sha256 "{result["artifact"]["sha256"]}"' in formula
    assert "@@" not in formula and "REPLACE" not in formula and "0" * 64 not in formula
    assert "getenv" not in formula and "ENV.fetch" not in formula
    with tarfile.open(archive) as archive_file:
        names = archive_file.getnames()
        prefix = builder.ARCHIVE_ROOT
        assert f"{prefix}/python/bin/python3.11" in names
        assert f"{prefix}/uv/uv" in names
        assert f"{prefix}/wheelhouse/app/requirements.txt" in names
        assert f"{prefix}/wheelhouse/analyzer/requirements.txt" in names
        assert f"{prefix}/source/theovex_polaris-0.3.3.tar.gz" in names
        assert f"{prefix}/app/bin/python" not in names and f"{prefix}/analyzer/bin/python" not in names
        assert not any("install-theo.sh" in name for name in names)
        link = archive_file.getmember(f"{prefix}/python/bin/python3")
        assert link.issym() and link.linkname == "python3.11"
        provenance = json.load(archive_file.extractfile(f"{prefix}/provenance.json"))
        assert len(provenance["bundle"]) == 7
        assert f"{prefix}/third-party-sources/source-packet.json" in names
        assert provenance["packageValidated"] is False
        assert provenance["analyzerRuntime"] == "not_checked"
        assert all(member.mtime == member.uid == member.gid == 0 for member in archive_file.getmembers())


def test_same_inputs_produce_same_artifact_and_https_does_not_publish(candidate, tmp_path):
    first = generate(candidate, tmp_path / "first", local_file=True)
    second = generate(candidate, tmp_path / "second", base_url="https://approved.example:8443/")
    assert first["artifact"]["sha256"] == second["artifact"]["sha256"]
    assert second["artifact"]["url"] == (
        f"https://approved.example:8443/releases/{builder.RELEASE_ID}/{builder.ARCHIVE_ROOT}.tar.gz"
    )
    assert second["publicationPerformed"] is False and second["downloadOrigin"] is None
    assert second["availability"] == "unpublished"


def test_existing_output_and_bundle_directories_are_never_modified(candidate, tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "user-file"
    sentinel.write_bytes(b"unchanged")
    with pytest.raises(ValueError, match="immutable"):
        generate(candidate, output, local_file=True)
    assert sentinel.read_bytes() == b"unchanged" and list(output.iterdir()) == [sentinel]
    with pytest.raises(ValueError, match="must not modify"):
        generate(candidate, candidate[0]["bundle_dir"] / "nested", local_file=True)
    with pytest.raises(ValueError, match="frozen"):
        generate(candidate, tmp_path / "theo-0.3.0-macos-arm64-r1" / "new", local_file=True)
    assert len(list(candidate[0]["bundle_dir"].iterdir())) == 7


@pytest.mark.parametrize("mode", [{}, {"local_file": True, "base_url": "https://approved.example"}])
def test_artifact_mode_is_explicit_and_exclusive(candidate, tmp_path, mode):
    with pytest.raises(ValueError, match="explicit"):
        generate(candidate, tmp_path / "output", **mode)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("origin", [
    "http://example.com", "https://user:do-not-echo@example.com",
    "https://example.com/path", "https://example.com/?token=do-not-echo",
    "https://example.com/#fragment", "https://example.com\\bad", "https://example.com:99999",
    "https://example.com\n", "https://éxample.com",
])
def test_https_origin_rejects_credentials_and_ambiguous_urls_without_echoing(origin):
    with pytest.raises(ValueError) as error:
        builder.https_origin(origin)
    assert origin not in str(error.value) and "do-not-echo" not in str(error.value)


@pytest.mark.parametrize("field,value", [
    ("id", "theo-0.3.0-macos-arm64-r1"), ("version", "0.3.0"), ("platform", "macos-x86_64"),
    ("minimumMacOS", "11.0"),
    ("availability", "published"), ("downloadOrigin", "https://invented.example"), ("modelIncluded", True),
])
def test_wrong_or_old_release_is_rejected_before_writes(candidate, tmp_path, field, value):
    inputs, manifest, *_ = candidate
    manifest[field] = value
    seal_bundle(inputs["bundle_dir"], manifest)
    with pytest.raises(ValueError):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("mutation", ["payload", "bootstrap", "manifest-pin", "extra-file", "runtime"])
def test_artifact_tampering_is_rejected_before_writes(candidate, tmp_path, mutation):
    inputs, manifest, *_ = candidate
    bundle = inputs["bundle_dir"]
    if mutation == "payload":
        (bundle / "payload.tar.gz").write_bytes(b"changed")
    elif mutation == "bootstrap":
        (bundle / "install-theo.sh").write_bytes(b"changed")
    elif mutation == "manifest-pin":
        manifest["hosts"] = ["not-resealed"]
        (bundle / "manifest.json").write_bytes(builder.json_bytes(manifest))
    elif mutation == "extra-file":
        (bundle / "unrelated").write_bytes(b"retained")
    else:
        manifest["runtimes"]["python"]["version"] = "3.11.999"
        seal_bundle(bundle, manifest)
    with pytest.raises(ValueError):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


def test_source_archive_must_match_the_public_wheel(candidate, tmp_path):
    inputs, _, source_files, _ = candidate
    source_files["theovex_polaris-0.3.3/src/polaris/cli.py"] = b"# Different source.\n"
    tar_bytes(inputs["source_archive"], source_files)
    with pytest.raises(ValueError, match="same package"):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


def test_payload_hash_lock_and_declared_versions_must_match(candidate, tmp_path):
    inputs, manifest, _, payload = candidate
    payload["app/requirements.txt"] = b"mcp==2.2.0\n"
    tar_bytes(inputs["bundle_dir"] / "payload.tar.gz", payload)
    manifest["payload"] = builder.artifact(inputs["bundle_dir"] / "payload.tar.gz")
    seal_bundle(inputs["bundle_dir"], manifest)
    with pytest.raises(ValueError, match="hash lock"):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("name,content", [
    ("../outside", b"x"), ("/absolute", b"x"), ("python/../outside", b"x"), ("python//double", b"x"),
    ("python/link", (tarfile.SYMTYPE, "/outside")),
    ("python/link", (tarfile.SYMTYPE, "../../outside")),
    ("python/link", (tarfile.SYMTYPE, "missing")),
    ("python/device", (tarfile.CHRTYPE, "")),
])
def test_runtime_tar_rejects_unsafe_paths_links_and_special_files(tmp_path, name, content):
    archive = tmp_path / "runtime.tar.gz"
    tar_bytes(archive, {name: content})
    with pytest.raises(ValueError):
        builder.inspect_tar(archive, {"python"}, links=True)


def test_archive_symlink_ancestors_cycles_and_duplicates_are_rejected(tmp_path):
    archive = tmp_path / "runtime.tar.gz"
    tar_bytes(archive, {"python/a": (tarfile.SYMTYPE, "b"), "python/b": (tarfile.SYMTYPE, "a")})
    with pytest.raises(ValueError, match="cycle"):
        builder.inspect_tar(archive, {"python"}, links=True)
    tar_bytes(archive, {"python/link": (tarfile.SYMTYPE, "target"),
                        "python/link/data": b"x", "python/target": b"x"})
    with pytest.raises(ValueError, match="traverses"):
        builder.inspect_tar(archive, {"python"}, links=True)
    with tarfile.open(archive, "w:gz") as output:
        output.addfile(tarfile.TarInfo("python/duplicate"))
        output.addfile(tarfile.TarInfo("python/duplicate"))
    with pytest.raises(ValueError, match="duplicate"):
        builder.inspect_tar(archive, {"python"}, links=True)

def test_archive_link_targets_cannot_use_an_alias_before_parent_traversal(tmp_path):
    archive = tmp_path / "runtime.tar.gz"
    tar_bytes(archive, {
        "python/bin/python": b"fixture",
        "python/alias": (tarfile.SYMTYPE, "."),
        "python/bad": (tarfile.SYMTYPE, "alias/../bin/python"),
    })
    with pytest.raises(ValueError, match="traverses"):
        builder.inspect_tar(archive, {"python"}, links=True)


def test_archive_hardlinks_become_regular_files_without_forward_link_dependencies(tmp_path):
    source, target = tmp_path / "source.tar.gz", tmp_path / "target.tar.gz"
    tar_bytes(source, {
        "uv-aarch64-apple-darwin/uvx": b"fixture bytes",
        "uv-aarch64-apple-darwin/uv": (tarfile.LNKTYPE, "uv-aarch64-apple-darwin/uvx"),
    })
    with tarfile.open(target, "w:gz") as archive:
        builder.add_tar(archive, source, {"uv-aarch64-apple-darwin"}, rename_root="uv", links=True)
    with tarfile.open(target) as archive:
        item = archive.getmember(f"{builder.ARCHIVE_ROOT}/uv/uv")
        assert item.isfile() and not item.islnk()
        assert archive.extractfile(item).read() == b"fixture bytes"


def test_public_archive_rejects_private_engine_modules(candidate, tmp_path):
    inputs, _, source_files, _ = candidate
    source_files["theovex_polaris-0.3.3/src/polaris/training.py"] = b"# Must never ship.\n"
    tar_bytes(inputs["source_archive"], source_files)
    with pytest.raises(ValueError):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


def test_source_archive_cannot_smuggle_nonpackage_data(candidate, tmp_path):
    inputs, _, source_files, _ = candidate
    source_files["theovex_polaris-0.3.3/private/data.json"] = b"{}"
    tar_bytes(inputs["source_archive"], source_files)
    with pytest.raises(ValueError, match="public package boundary"):
        generate(candidate, tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


def test_archive_size_and_count_limits_are_enforced(tmp_path, monkeypatch):
    archive = tmp_path / "runtime.tar.gz"
    tar_bytes(archive, {"python/a": b"1234", "python/b": b"1234"})
    monkeypatch.setattr(builder, "MAX_EXPANDED", 7)
    with pytest.raises(ValueError, match="excessive"):
        builder.inspect_tar(archive, {"python"})
    monkeypatch.setattr(builder, "MAX_EXPANDED", 100)
    monkeypatch.setattr(builder, "MAX_MEMBERS", 1)
    with pytest.raises(ValueError, match="excessive"):
        builder.inspect_tar(archive, {"python"})


@pytest.mark.parametrize("tag", ["cp312-cp312-macosx_11_0_arm64", "cp311-cp311-macosx_11_0_x86_64",
                               "cp311-cp311-manylinux_2_17_aarch64"])
def test_incompatible_wheels_are_rejected(tag):
    with pytest.raises(ValueError, match="CPython 3.11"):
        builder.wheel_identity(wheel_bytes("example", "1.0", tag=tag))


def test_artifact_symlinks_are_rejected(candidate, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(candidate[0]["bundle_dir"], target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        builder.build(bundle_dir=alias, source_archive=candidate[0]["source_archive"],
                      output=tmp_path / "output", local_file=True)
    assert not (tmp_path / "output").exists()


def test_formula_contract_is_isolated_and_does_not_claim_analyzer_acceptance(candidate, tmp_path):
    generate(candidate, tmp_path / "output", local_file=True)
    formula = (tmp_path / "output/polaris.rb").read_text()
    assert '%w[app analyzer]' in formula
    assert '{ "polaris" => "polaris", "theo" => "polaris.onboarding" }' in formula
    assert '-I -B -m #{entrypoint} "$@"' in formula
    assert '"--require-hashes", "--no-build", "--link-mode", "copy"' in formula
    assert "deny_network_access!" in formula
    assert "depends_on macos: :sequoia" in formula
    assert "--root #{Shellwords.escape(testpath.to_s)}" in formula
    assert '"manager" => "homebrew"' in formula and '"format" => "polaris.theo-install/2"' in formula
    assert '"packageValidated" => true, "analyzerRuntime" => "not_checked"' in formula
    assert 'system "/usr/bin/env", "-i", *clean_env' in formula
    assert "def post_install" not in formula and "virtualenv_install_with_resources" not in formula
    assert '"/usr/bin/sandbox-exec"' not in formula and "--no-sandbox" not in formula
    assert "Gatekeeper doesn't block" not in formula
    assert "theo setup" in formula and 'bin/"theo", "setup"' not in formula


def test_macos_only_formula_scopes_version_floor_to_homebrew_platform_block(candidate, tmp_path):
    generate(candidate, tmp_path / "output", local_file=True)
    formula = (tmp_path / "output/polaris.rb").read_text()
    assert (
        "  depends_on :macos\n"
        "  on_macos do\n"
        "    depends_on macos: :sequoia\n"
        "  end\n"
        "  depends_on arch: :arm64\n"
    ) in formula
    assert formula.count("depends_on macos:") == 1


@pytest.mark.parametrize("prefix_name", ["custom prefix", "custom prefix's [literal] $name;"])
def test_formula_test_commands_quote_executables_without_running_them(candidate, tmp_path, prefix_name):
    generate(candidate, tmp_path / "output", local_file=True)
    formula = (tmp_path / "output/polaris.rb").read_text()
    test_block = formula.split("  test do\n", 1)[1]
    assert "#{bin}/" not in test_block
    assignments = [
        line.strip() for line in test_block.splitlines()
        if line.strip().startswith(("polaris_command = ", "theo_command = "))
    ]
    assert assignments == [
        'polaris_command = Shellwords.escape((bin/"polaris").to_s)',
        'theo_command = Shellwords.escape((bin/"theo").to_s)',
    ]
    # Evaluate only the four generated string expressions, not the formula DSL or commands.
    commands = re.findall(
        r'shell_output\(\s*((?:"(?:\\.|[^"\\])*"\s*\\?\s*)+)(?:,\s*[01])?\s*\)',
        test_block,
    )
    assert len(commands) == 4
    ruby = shutil.which("ruby")
    if not ruby:
        pytest.skip("Ruby is unavailable; formula command quoting still needs host validation.")
    bin_path = tmp_path / prefix_name / "Cellar/polaris/0.3.3/bin"
    project_path = tmp_path / "project's [literal] $name;"
    script = (
        'require "json"\nrequire "pathname"\nrequire "shellwords"\n'
        'bin = Pathname.new(ARGV.fetch(0))\ntestpath = Pathname.new(ARGV.fetch(1))\n'
        + "\n".join(assignments)
        + "\ncommands = [\n" + ",\n".join(commands) + "\n]\n"
        + "puts JSON.generate(commands.map { |command| Shellwords.split(command) })\n"
    )
    result = subprocess.run(
        [ruby, "-e", script, str(bin_path), str(project_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    scan_options = ["--root", str(project_path), "--engine", "rules", "--model-source",
                    "local", "--no-cache", "--format", "json"]
    assert json.loads(result.stdout) == [
        [str(bin_path / "polaris"), "--version"],
        [str(bin_path / "theo"), "--version"],
        [str(bin_path / "polaris"), "scan", "app.py", *scan_options],
        [str(bin_path / "polaris"), "scan", "safe.py", *scan_options],
    ]


def test_generated_ruby_syntax_and_unrendered_template_refusal(candidate, tmp_path):
    ruby = shutil.which("ruby")
    if not ruby:
        pytest.skip("Ruby is unavailable; generated formula syntax still needs host validation.")
    generate(candidate, tmp_path / "output", local_file=True)
    checked = subprocess.run([ruby, "-c", str(tmp_path / "output/polaris.rb")],
                             capture_output=True, text=True, check=False)
    assert checked.returncode == 0, checked.stderr
    template = subprocess.run([ruby, str(ROOT / "packaging/homebrew/polaris.rb")],
                              capture_output=True, text=True, check=False)
    assert template.returncode != 0
    assert "Generate a pinned candidate" in template.stderr


def test_cli_argument_error_never_echoes_a_supplied_value():
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/build_homebrew_formula.py"),
                             "--unknown=synthetic-do-not-echo"],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "synthetic-do-not-echo" not in result.stdout + result.stderr

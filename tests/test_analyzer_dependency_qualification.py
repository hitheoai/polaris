"""Synthetic wheel fixtures only; no fetched packages are installed or executed."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import stat
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "analyzer_qualification_test", ROOT / "scripts/qualify_analyzer_dependencies.py",
)
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)

OLD = "semgrep-1.178.0"
NEW = "semgrep-1.178.0+theovex.1"


def fixture_wheel(tmp_path, *, overrides=None, record_transform=None, special=None, duplicate=False):
    metadata = (
        "Metadata-Version: 2.4\nName: semgrep\nVersion: 1.178.0\nRequires-Python: >=3.10\n"
        + "".join(f"Requires-Dist: {value}\n" for value in qualification.UPSTREAM_REQUIREMENTS)
        + "\nDescription includes Version: 1.178.0 and pyjwt[crypto]~=2.13.0 unchanged.\n"
    ).encode()
    members = {
        f"{OLD}.dist-info/METADATA": metadata,
        f"{OLD}.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\n"
            b"Root-Is-Purelib: false\nTag: cp311-none-macosx_11_0_arm64\n\n"
        ),
        f"{OLD}.dist-info/licenses/LICENSE": b"Unmodified upstream license fixture.\n",
        f"{OLD}.dist-info/entry_points.txt": b"[console_scripts]\nsemgrep = semgrep.main:main\n",
        f"{OLD}.data/purelib/semgrep/__init__.py": b'__VERSION__ = "1.178.0"\n',
        f"{OLD}.data/purelib/semgrep/bin/semgrep-core": b"\xcf\xfa\xed\xfe synthetic native data",
        **(overrides or {}),
    }
    record_name = f"{OLD}.dist-info/RECORD"
    rows = [
        [name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(),
         str(len(data))]
        for name, data in sorted(members.items())
    ] + [[record_name, "", ""]]
    if record_transform:
        rows = record_transform(rows)
    text = io.StringIO(newline="")
    csv.writer(text, lineterminator="\n").writerows(rows)
    members[record_name] = text.getvalue().encode()
    path = tmp_path / "upstream.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if name.endswith("semgrep-core") else 0o644)) << 16
            if special == name:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, data)
        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate"):
                archive.writestr(next(iter(members)), b"duplicate")
    return path


def approve_fixture(monkeypatch, path):
    monkeypatch.setattr(qualification, "UPSTREAM_BYTES", path.stat().st_size)
    monkeypatch.setattr(qualification, "UPSTREAM_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())


def test_derivative_preserves_payload_and_is_reproducible(tmp_path, monkeypatch):
    source = fixture_wheel(tmp_path)
    approve_fixture(monkeypatch, source)
    first = qualification.derive(source, tmp_path / "first")
    second = qualification.derive(source, tmp_path / "second")
    assert first["derived"] == second["derived"]
    assert first["implementationNativeLicenseBytesUnchanged"]
    assert not first["runtimeCompatibilityTested"] and not first["releaseQualified"]
    changes = [item for item in first["members"] if not item["contentUnchanged"]]
    assert {item["upstreamPath"] for item in changes} == {
        f"{OLD}.dist-info/METADATA", f"{OLD}.dist-info/WHEEL", f"{OLD}.dist-info/RECORD",
    }
    wheel = tmp_path / "first" / first["derived"]["name"]
    inspected = qualification.inspect_wheel(wheel)
    assert inspected["version"] == qualification.LOCAL_VERSION
    assert qualification.LOCAL_REQUIREMENT in inspected["requiresDist"]
    assert qualification.UPSTREAM_REQUIREMENT not in inspected["requiresDist"]
    with zipfile.ZipFile(wheel) as archive:
        assert b"Description includes Version: 1.178.0 and pyjwt[crypto]~=2.13.0 unchanged." in archive.read(
            f"{NEW}.dist-info/METADATA",
        )
        assert archive.read(f"{NEW}.data/purelib/semgrep/__init__.py") == b'__VERSION__ = "1.178.0"\n'
    assert json.loads((tmp_path / "first/recipe.json").read_text()) == first


def test_real_approved_pin_cannot_be_bypassed_by_cli_inputs(tmp_path):
    source = fixture_wheel(tmp_path)
    with pytest.raises(ValueError, match="approved size and SHA-256"):
        qualification.derive(source, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_wrong_digest_same_size_is_rejected(tmp_path, monkeypatch):
    source = fixture_wheel(tmp_path)
    monkeypatch.setattr(qualification, "UPSTREAM_BYTES", source.stat().st_size)
    with pytest.raises(ValueError, match="approved size and SHA-256"):
        qualification.derive(source, tmp_path / "output")


@pytest.mark.parametrize("path", [
    "../outside", "/absolute", "a/../outside", "a//b", "a\\b", "C:outside", "a/./b", "bad\nname",
])
def test_unsafe_member_paths_are_rejected(tmp_path, path):
    source = fixture_wheel(tmp_path, overrides={path: b"data"})
    with pytest.raises(ValueError, match="Unsafe"):
        qualification.inspect_wheel(source)


def test_symlink_members_are_rejected(tmp_path):
    name = f"{OLD}.data/purelib/semgrep/__init__.py"
    source = fixture_wheel(tmp_path, special=name)
    with pytest.raises(ValueError, match="special"):
        qualification.inspect_wheel(source)


def test_duplicate_members_are_rejected(tmp_path):
    source = fixture_wheel(tmp_path, duplicate=True)
    with pytest.raises(ValueError, match="duplicate"):
        qualification.inspect_wheel(source)


def test_case_collisions_are_rejected(tmp_path):
    source = fixture_wheel(tmp_path, overrides={f"{OLD}.dist-info/metadata": b"collision"})
    with pytest.raises(ValueError, match="colliding"):
        qualification.inspect_wheel(source)


def test_parent_file_conflict_is_rejected(tmp_path):
    source = fixture_wheel(tmp_path, overrides={f"{OLD}.data/purelib/semgrep": b"file"})
    with pytest.raises(ValueError, match="conflicting"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("transform", [
    lambda rows: rows[:-1],
    lambda rows: rows + [rows[0]],
    lambda rows: [[row[0], "sha256=wrong", row[2]] if row[1] else row for row in rows],
    lambda rows: [[row[0], row[1], "0"] if row[1] else row for row in rows],
    lambda rows: [["not-present", *row[1:]] if index == 0 else row for index, row in enumerate(rows)],
    lambda rows: [row + ["extra"] for row in rows],
])
def test_invalid_record_never_passes(tmp_path, transform):
    source = fixture_wheel(tmp_path, record_transform=transform)
    with pytest.raises(ValueError, match="RECORD"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("suffix", ["RECORD.jws", "RECORD.p7s"])
def test_upstream_signatures_are_not_transplanted(tmp_path, suffix):
    source = fixture_wheel(tmp_path, overrides={f"{OLD}.dist-info/{suffix}": b"signature fixture"})
    with pytest.raises(ValueError, match="no signature is inherited"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("metadata", [
    b"Metadata-Version: 2.4\nName: semgrep\nVersion: 1.178.0\nVersion: 1.178.0\n\n",
    b"Metadata-Version: 2.4\nName: semgrep\nName: semgrep\nVersion: 1.178.0\n\n",
    b"Metadata-Version: 2.4\nName: semgrep\nVersion: 1.177.0\n\n",
])
def test_ambiguous_or_wrong_identity_is_rejected(tmp_path, metadata):
    source = fixture_wheel(tmp_path, overrides={f"{OLD}.dist-info/METADATA": metadata})
    with pytest.raises(ValueError, match="ambiguous|disagree"):
        qualification.inspect_wheel(source)


def test_unexpected_requirements_are_not_silently_relaxed(tmp_path, monkeypatch):
    source = fixture_wheel(tmp_path, overrides={
        f"{OLD}.dist-info/METADATA": b"Metadata-Version: 2.4\nName: semgrep\nVersion: 1.178.0\nRequires-Dist: jwt\n\n",
    })
    approve_fixture(monkeypatch, source)
    with pytest.raises(ValueError, match="requirements"):
        qualification.derive(source, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_old_outputs_and_path_links_are_rejected(tmp_path, monkeypatch):
    source = fixture_wheel(tmp_path)
    approve_fixture(monkeypatch, source)
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "untouched"
    marker.write_text("preserve")
    with pytest.raises(FileExistsError):
        qualification.derive(source, output)
    assert marker.read_text() == "preserve"
    link = tmp_path / "link"
    link.symlink_to(output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        qualification.derive(source, link / "new")
    input_link = tmp_path / "input-link"
    input_link.symlink_to(source)
    with pytest.raises(ValueError, match="symlinks"):
        qualification.inspect_wheel(input_link)


def test_archive_bounds_are_enforced(tmp_path, monkeypatch):
    source = fixture_wheel(tmp_path)
    monkeypatch.setattr(qualification, "MAX_EXPANDED_BYTES", 1)
    with pytest.raises(ValueError, match="expanded byte bound"):
        qualification.inspect_wheel(source)
    monkeypatch.setattr(qualification, "MAX_ARCHIVE_BYTES", 1)
    with pytest.raises(ValueError, match="bounded regular file"):
        qualification.inspect_wheel(source)


def test_exact_header_replacement_does_not_touch_body():
    original = b"Version: 1.178.0\n\nVersion: 1.178.0\n"
    assert qualification.replace_header(original, "Version", "1.178.0", "local") == (
        b"Version: local\n\nVersion: 1.178.0\n"
    )
    for value in (b"Version: other\n\n", b"Version: 1.178.0\r\n\r\n", b"Version: 1.178.0\nVersion: 1.178.0\n\n"):
        with pytest.raises(ValueError):
            qualification.replace_header(value, "Version", "1.178.0", "local")


@pytest.mark.parametrize("parent,child", [
    ("Cache", "cache/value.py"),
    ("caf\u00e9", "cafe\u0301/value.py"),
])
def test_case_and_unicode_ancestor_aliases_are_rejected(tmp_path, parent, child):
    prefix = f"{OLD}.data/purelib/semgrep/"
    source = fixture_wheel(tmp_path, overrides={prefix + parent: b"file", prefix + child: b"data"})
    with pytest.raises(ValueError, match="conflicting"):
        qualification.inspect_wheel(source)


def test_unicode_full_name_aliases_are_rejected(tmp_path):
    prefix = f"{OLD}.data/purelib/semgrep/"
    source = fixture_wheel(tmp_path, overrides={prefix + "caf\u00e9": b"a", prefix + "cafe\u0301": b"b"})
    with pytest.raises(ValueError, match="colliding"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("alias", [
    "semgrep/__init__.py",
    f"{OLD}.data/platlib/semgrep/__init__.py",
    "SEMGREP/__INIT__.py",
])
def test_wheel_spread_aliases_are_rejected(tmp_path, alias):
    source = fixture_wheel(tmp_path, overrides={alias: b"conflicting installed payload"})
    with pytest.raises(ValueError, match="installation destinations collide"):
        qualification.inspect_wheel(source)


def test_wheel_spread_ancestor_alias_is_rejected(tmp_path):
    source = fixture_wheel(tmp_path, overrides={"SEMGREP": b"conflicting installed file"})
    with pytest.raises(ValueError, match="installation destinations have conflicting"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("scheme", ["scripts", "headers", "data", "unrecognized"])
def test_unknown_target_installation_schemes_fail_closed(tmp_path, scheme):
    source = fixture_wheel(tmp_path, overrides={f"{OLD}.data/{scheme}/payload": b"data"})
    with pytest.raises(ValueError, match="Unsupported wheel installation scheme"):
        qualification.inspect_wheel(source)


@pytest.mark.parametrize("mutation", ["python", "native", "metadata", "wheel", "record"])
def test_self_consistent_post_write_mutation_is_rejected(tmp_path, monkeypatch, mutation):
    source = fixture_wheel(tmp_path)
    approve_fixture(monkeypatch, source)
    inspect = qualification.inspect_wheel

    def corrupt_then_inspect(path):
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            contents = {entry.filename: archive.read(entry) for entry in entries}
        member = {
            "python": f"{NEW}.data/purelib/semgrep/__init__.py",
            "native": f"{NEW}.data/purelib/semgrep/bin/semgrep-core",
            "metadata": f"{NEW}.dist-info/METADATA",
            "wheel": f"{NEW}.dist-info/WHEEL",
            "record": f"{NEW}.dist-info/RECORD",
        }[mutation]
        if mutation in ("python", "native"):
            contents[member] += b"unauthorized payload"
        elif mutation == "metadata":
            contents[member] = contents[member].replace(b"\n\n", b"\nX-Unapproved: change\n\n", 1)
        elif mutation == "wheel":
            contents[member] = contents[member].replace(b"Root-Is-Purelib: false", b"Root-Is-Purelib: true")
        record_name = f"{NEW}.dist-info/RECORD"
        rows = [
            [name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(), str(len(data))]
            for name, data in contents.items() if name != record_name
        ] + [[record_name, "", ""]]
        text = io.StringIO(newline="")
        csv.writer(text, lineterminator="\n").writerows(sorted(rows, reverse=mutation == "record"))
        contents[record_name] = text.getvalue().encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for entry in entries:
                archive.writestr(entry, contents[entry.filename])
        path.write_bytes(output.getvalue())
        return inspect(path)

    monkeypatch.setattr(qualification, "inspect_wheel", corrupt_then_inspect)
    with pytest.raises(ValueError, match="unapproved payload|exact approved bytes"):
        qualification.derive(source, tmp_path / "mutated")
    assert not (tmp_path / "mutated/recipe.json").exists()

"""Generate an unpublished, pinned Homebrew binary distribution; never install or publish it.

Use --local-file for a local artifact URL or supply an explicitly approved HTTPS --base-url.
The new bundle, source packet and matching public source archive must already exist.
Runtime archives and wheelhouses are inspected and repackaged, not executed or resolved.
"""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import stat
import tarfile
import tomllib
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.3"
RELEASE_ID = f"theo-{VERSION}-macos-arm64-r1"
SIGNED_RELEASE_ID = f"theo-{VERSION}-macos-arm64-r2"
PLATFORM = "macos-arm64"
MINIMUM_MACOS = "15.0"
MAX_ARTIFACT = 1_000_000_000
MAX_EXPANDED = 1_500_000_000
MAX_MEMBERS = 30_000
ARCHIVE_ROOT = f"{RELEASE_ID}-homebrew"


def helper(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("homebrew_" + name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def regular_path(path: Path) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Artifact and output paths must not traverse symlinks.")
    return path


def read(path: Path, *, limit: int = 2_000_000) -> bytes:
    path = regular_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Artifact is not a bounded nonempty regular file.")
        content = stream.read(limit + 1)
        if len(content) != info.st_size:
            raise ValueError("Artifact changed during inspection.")
        return content


def artifact(path: Path, *, allow_empty: bool = False) -> dict[str, Any]:
    path = regular_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not int(not allow_empty) <= info.st_size <= MAX_ARTIFACT:
            raise ValueError("Artifact is not a bounded nonempty regular file.")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise ValueError("Artifact changed during inspection.")
    return {"name": path.name, "sha256": digest, "bytes": info.st_size}


def verify(path: Path, pin: dict[str, Any], *, allow_empty: bool = False) -> dict[str, Any]:
    if (not isinstance(pin, dict) or type(pin.get("bytes")) is not int
            or not int(not allow_empty) <= pin["bytes"] <= MAX_ARTIFACT
            or not re.fullmatch(r"[a-f0-9]{64}", str(pin.get("sha256", "")))):
        raise ValueError("Artifact requires an exact size and SHA256.")
    observed = artifact(path, allow_empty=allow_empty)
    if any(observed[key] != pin[key] for key in ("bytes", "sha256")):
        raise ValueError("Artifact does not match its size or SHA256.")
    return observed


def archive_name(value: str) -> str:
    if (not value or "\\" in value or "\0" in value or value.startswith("/")
            or any(part in ("", ".", "..") for part in value.rstrip("/").split("/"))):
        raise ValueError("Archive contains an unsafe path.")
    return value.rstrip("/")


def inspect_tar(path: Path, roots: set[str], *, links: bool = False) -> list[tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    targets: dict[str, str] = {}
    raw_targets: dict[str, str] = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = archive_name(member.name)
            total += member.size
            if (name.split("/")[0] not in roots or name in members or member.size < 0
                    or total > MAX_EXPANDED or len(members) >= MAX_MEMBERS
                    or member.mode & 0o7000):
                raise ValueError("Archive contains duplicate, excessive or unsafe entries.")
            if member.issym() or member.islnk():
                if not links or member.linkname.startswith("/") or "\\" in member.linkname:
                    raise ValueError("Archive link is not permitted.")
                raw_target = (
                    posixpath.join(posixpath.dirname(name), member.linkname)
                    if member.issym() else member.linkname
                )
                target = posixpath.normpath(raw_target)
                if target.split("/")[0] != name.split("/")[0]:
                    raise ValueError("Archive link escapes its runtime.")
                targets[name] = archive_name(target)
                raw_targets[name] = raw_target
            elif not (member.isfile() or member.isdir()):
                raise ValueError("Archive contains a special file.")
            members[name] = member
    for name in members:
        if any(str(parent) in targets for parent in PurePosixPath(name).parents):
            raise ValueError("Archive entry traverses another archive link.")
    for raw_target in raw_targets.values():
        parts: list[str] = []
        for part in raw_target.split("/"):
            if "/".join(parts) in targets:
                raise ValueError("Archive link target traverses another archive link.")
            if part == "..":
                if len(parts) <= 1:
                    raise ValueError("Archive link escapes its runtime.")
                parts.pop()
            elif part not in ("", "."):
                parts.append(part)
    for name, target in targets.items():
        seen = {name}
        while target in targets:
            if target in seen or len(seen) > 32:
                raise ValueError("Archive contains a link cycle.")
            seen.add(target)
            target = targets[target]
        if target not in members and not any(item.startswith(target + "/") for item in members):
            raise ValueError("Archive contains a dangling link.")
        if members[name].islnk() and (target not in members or not members[target].isfile()):
            raise ValueError("Archive hardlink must resolve to a regular file.")
    return list(members.values())


def normalized(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def public_builder() -> Any:
    spec = importlib.util.spec_from_file_location("homebrew_public_builder", ROOT / "scripts/build_public_wheel.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wheel_identity(content: bytes) -> tuple[str, str, dict[str, str]]:
    with zipfile.ZipFile(io.BytesIO(content)) as wheel:
        entries = wheel.infolist()
        names = [entry.filename for entry in entries if not entry.is_dir()]
        if (len(entries) > MAX_MEMBERS or len(names) != len(set(names))
                or sum(entry.file_size for entry in entries) > MAX_EXPANDED):
            raise ValueError("Wheel has excessive or duplicate entries.")
        for entry in entries:
            archive_name(entry.filename)
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("Wheel contains a link.")
        metadata = [name for name in names if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or wheel.getinfo(metadata[0]).file_size > 2_000_000:
            raise ValueError("Wheel metadata is ambiguous or excessive.")
        wheel_path = metadata[0].rsplit("/", 1)[0] + "/WHEEL"
        if wheel.getinfo(wheel_path).file_size > 2_000_000:
            raise ValueError("Wheel tags exceed their byte bound.")
        tags = email.parser.BytesParser().parsebytes(wheel.read(wheel_path)).get_all("Tag", [])
        if not any(supported_tag(tag) for tag in tags):
            raise ValueError("Wheel must support CPython 3.11 on Apple Silicon macOS.")
        info = email.parser.BytesParser().parsebytes(wheel.read(metadata[0]))
        name, version = info.get("Name", ""), info.get("Version", "")
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version)):
            raise ValueError("Wheel metadata is invalid.")
        package = {}
        if normalized(name) == "theovex-polaris":
            public = public_builder()
            try:
                public.check_contents(names, "Homebrew wheel")
            except SystemExit:
                raise ValueError("Wheel violates the public source boundary.") from None
            entrypoints = metadata[0].rsplit("/", 1)[0] + "/entry_points.txt"
            if wheel.getinfo(entrypoints).file_size > 2_000_000:
                raise ValueError("Entry points exceed their byte bound.")
            points = wheel.read(entrypoints).decode("utf-8")
            if ("theo = polaris.onboarding.cli:main" not in points
                    or "polaris = polaris.cli:main" not in points):
                raise ValueError("Both console entry points must be present.")
            package = {inner: hashlib.sha256(wheel.read(outer)).hexdigest()
                       for inner, outer in public.package_files(names).items()}
        return normalized(name), version, package

def supported_tag(tag: str) -> bool:
    pieces = tag.split("-")
    if len(pieces) != 3:
        return False
    python, abi, platform = pieces
    python_ok = ("py3" in python.split(".") and abi == "none"
                 or python == "cp311" and abi in ("cp311", "abi3", "none")
                 or re.fullmatch(r"cp3(?:[6-9]|10)", python) is not None and abi == "abi3")
    platform_ok = any(part == "any" or re.fullmatch(r"macosx_[0-9]+_[0-9]+_(arm64|universal2)", part)
                      for part in platform.split("."))
    return bool(python_ok and platform_ok)


def inspect_payload(path: Path, manifest: dict[str, Any], *,
                    signed_members: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    delivery = helper("analyzer_delivery")
    delivery.validate_manifest(manifest)
    members = inspect_tar(path, {"app", "analyzer"})
    files = {member.name: member for member in members if member.isfile()}
    package: dict[str, str] = {}
    with tarfile.open(path, "r:gz") as archive:
        for component in ("app", "analyzer"):
            expected = manifest["environments"][component]
            observed, requirements = {}, []
            lock_name = f"{component}/requirements.txt"
            if lock_name not in files or files[lock_name].size > 2_000_000:
                raise ValueError("Payload lacks a bounded dependency lock.")
            for name, member in files.items():
                if not name.startswith(component + "/") or name == lock_name:
                    continue
                parts = name.split("/")
                if len(parts) != 3 or parts[1] != "wheels" or not parts[2].endswith(".whl"):
                    raise ValueError("Payload contains a non-wheel dependency artifact.")
                if member.size > 250_000_000:
                    raise ValueError("Dependency wheel exceeds its byte bound.")
                stream = archive.extractfile(member)
                assert stream is not None
                content = stream.read()
                distribution, version, source_files = wheel_identity(content)
                if component == "analyzer":
                    inspected = delivery.validate_wheel(content, signed_members=signed_members)
                    pin = delivery.identity().contract()["packages"][inspected["name"]]
                    if parts[2] != pin["filename"]:
                        raise ValueError("Analyzer wheel filename differs from its exact artifact identity.")
                if distribution in observed:
                    raise ValueError("Payload contains a duplicate distribution.")
                observed[distribution] = version
                requirements.append(delivery.requirements_line(
                    distribution, version, hashlib.sha256(content).hexdigest(), component=component,
                ))
                if source_files:
                    if component != "app" or package:
                        raise ValueError("Public package must occur only in the app environment.")
                    package = source_files
            stream = archive.extractfile(files[lock_name])
            assert stream is not None
            if (stream.read().decode("utf-8") != "\n".join(sorted(requirements)) + "\n"
                    or observed != expected):
                raise ValueError("Payload wheel inventory or hash lock is inconsistent.")
    if not package or manifest["environments"]["app"].get("theovex-polaris") != VERSION:
        raise ValueError("Payload must retain the separately pinned public application.")
    return package


def inspect_source(path: Path, package: dict[str, str], *, version: str = VERSION) -> None:
    root = f"theovex_polaris-{version}"
    members = inspect_tar(path, {root})
    files = {member.name: member for member in members if member.isfile()}
    top_level = {"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "NOTICE"}
    observed = {}
    with tarfile.open(path, "r:gz") as archive:
        for name, member in files.items():
            inner = name.removeprefix(root + "/")
            if not inner.startswith("src/polaris/") and inner not in top_level:
                raise ValueError("Source archive exceeds the public package boundary.")
            if member.size > 20_000_000:
                raise ValueError("Source file exceeds its byte bound.")
            stream = archive.extractfile(member)
            assert stream is not None
            content = stream.read()
            if inner.startswith("src/polaris/"):
                observed[inner.removeprefix("src/polaris/")] = hashlib.sha256(content).hexdigest()
            if inner == "pyproject.toml":
                project = tomllib.loads(content.decode("utf-8"))["project"]
                if project["name"] != "theovex-polaris" or project["version"] != version:
                    raise ValueError("Source archive has the wrong package identity.")
    if (not observed or observed != package
            or not all(f"{root}/{name}" in files for name in top_level - {"PKG-INFO"})):
        raise ValueError("Public wheel and source archive do not contain the same package.")


def https_origin(value: str) -> str:
    try:
        url = urllib.parse.urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment or "\\" in value
                or not value.isascii() or any(char.isspace() or ord(char) < 33 for char in value)
                or not re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", url.netloc)
                or url.port is not None and not 0 < url.port <= 65535):
            raise ValueError
    except ValueError:
        raise ValueError("Use a credential-free approved HTTPS origin without a path, query or fragment.") from None
    return f"https://{url.netloc}"


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def add_bytes(archive: tarfile.TarFile, name: str, content: bytes, *,
              archive_root: str = ARCHIVE_ROOT) -> None:
    member = tarfile.TarInfo(f"{archive_root}/{name}")
    member.size, member.mode = len(content), 0o644
    archive.addfile(member, io.BytesIO(content))


def add_tar(archive: tarfile.TarFile, path: Path, roots: set[str], *,
            prefix: str = "", rename_root: str | None = None, links: bool = False,
            archive_root: str = ARCHIVE_ROOT) -> None:
    members = inspect_tar(path, roots, links=links)
    with tarfile.open(path, "r:gz") as source:
        indexed = {member.name.rstrip("/"): member for member in members}
        for old in sorted(members, key=lambda member: member.name):
            name = old.name.rstrip("/")
            if rename_root:
                name = rename_root + name[name.index("/"):] if "/" in name else rename_root
            item = tarfile.TarInfo(f"{archive_root}/{prefix}{name}")
            item.type, item.size = old.type, old.size
            item.mode = 0o755 if old.isdir() or old.mode & 0o111 else 0o644
            if old.issym():
                item.linkname = old.linkname
            if old.islnk():
                target = old
                while target.islnk() or target.issym():
                    target_name = posixpath.normpath(
                        posixpath.join(posixpath.dirname(target.name), target.linkname)
                        if target.issym() else target.linkname,
                    )
                    target = indexed[target_name]
                item.type, item.size = tarfile.REGTYPE, target.size
                item.mode = 0o755 if target.mode & 0o111 else 0o644
                stream = source.extractfile(target)
            else:
                stream = source.extractfile(old) if old.isfile() else None
            try:
                archive.addfile(item, stream)
            finally:
                if stream:
                    stream.close()


def add_file(archive: tarfile.TarFile, name: str, path: Path, *,
             archive_root: str = ARCHIVE_ROOT) -> None:
    member = tarfile.TarInfo(f"{archive_root}/{name}")
    member.size, member.mode = path.stat().st_size, 0o644
    with path.open("rb") as stream:
        archive.addfile(member, stream)


def native_inventory(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location(
        "homebrew_native", Path(__file__).with_name("release_native.py"),
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inventory(bundle, manifest)


def inspect_bundle(bundle_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    bundle_dir = regular_path(bundle_dir)
    manifest_raw = read(bundle_dir / "manifest.json")
    manifest = json.loads(manifest_raw)
    release = json.loads(read(bundle_dir / "bootstrap.json"))
    if not isinstance(manifest, dict) or manifest.get("id") not in (RELEASE_ID, SIGNED_RELEASE_ID):
        raise ValueError("Bundle has an unsupported immutable release identity.")
    release_id = manifest["id"]
    for document, format_name in ((manifest, "polaris.theo-bundle/1"), (release, "polaris.onboarding-release/1")):
        if (not isinstance(document, dict) or document.get("format") != format_name or document.get("id") != release_id
                or document.get("version") != VERSION or document.get("platform") != PLATFORM
                or document.get("minimumMacOS") != MINIMUM_MACOS
                or document.get("availability") != "unpublished" or document.get("downloadOrigin") is not None
                or document.get("apiOrigin") is not None):
            raise ValueError("Only the matching new unpublished release may be packaged.")
    if (manifest.get("modelIncluded") is not False or not isinstance(manifest.get("environments"), dict)
            or not all(isinstance(manifest["environments"].get(name), dict) for name in ("app", "analyzer"))):
        raise ValueError("Manifest must identify both environments and exclude model artifacts.")
    manifest_pin = artifact(bundle_dir / "manifest.json")
    verify(bundle_dir / "install-theo.sh", release["bootstrap"])
    bootstrap = read(bundle_dir / "install-theo.sh")
    pin_line = f"MANIFEST_SHA256='{manifest_pin['sha256']}'".encode()
    if bootstrap.splitlines().count(pin_line) != 1:
        raise ValueError("Bootstrap does not pin the inspected manifest.")
    runtime_pins = json.loads(read(ROOT / "packaging/installer/runtime-pins.json"))
    paths = [bundle_dir / name for name in ("manifest.json", "bootstrap.json", "install-theo.sh", "payload.tar.gz")]
    verify(bundle_dir / "payload.tar.gz", manifest["payload"])
    sources = helper("source_delivery")
    source_pin = manifest.get("thirdPartySources", {})
    sources.validate_archive(
        bundle_dir / sources.ARCHIVE_NAME, source_pin,
        required_artifacts={manifest.get("analyzerIdentity", {}).get("derivativeWheelSha256")},
    )
    paths.append(bundle_dir / sources.ARCHIVE_NAME)
    signed = release_id == SIGNED_RELEASE_ID
    signed_members = None
    for name, root in (("python", "python"), ("uv", "uv-aarch64-apple-darwin")):
        pin = manifest["runtimes"][name]
        if signed:
            if (pin.get("upstream") != runtime_pins[name] or pin.get("version") != runtime_pins[name]["version"]
                    or pin.get("transformation") != "developer-id-signing"
                    or pin.get("name") != f"{name}-developer-id.tar.gz"):
                raise ValueError("Signed runtime must preserve its exact upstream provenance.")
        elif pin != runtime_pins[name]:
            raise ValueError("Unsigned runtime must match the inspected upstream pin.")
        path = bundle_dir / pin["name"]
        paths.append(path)
        verify(path, pin)
        inspect_tar(path, {root}, links=True)
    if signed:
        if (manifest.get("signing", {}).get("name") != "signing-report.json"
                or manifest.get("compliance", {}).get("name") != "compliance.tar.gz"):
            raise ValueError("Signed bundle requires pinned signing and compliance evidence.")
        for field in ("signing", "compliance"):
            path = bundle_dir / manifest[field]["name"]
            verify(path, manifest[field])
            paths.append(path)
        inspect_tar(bundle_dir / "compliance.tar.gz", {"compliance"})
        report = json.loads(read(bundle_dir / "signing-report.json", limit=20_000_000))
        expected = {"payload.tar.gz": artifact(bundle_dir / "payload.tar.gz"),
                    "compliance.tar.gz": artifact(bundle_dir / "compliance.tar.gz"),
                    sources.ARCHIVE_NAME: artifact(bundle_dir / sources.ARCHIVE_NAME),
                    **{manifest["runtimes"][name]["name"]: artifact(bundle_dir / manifest["runtimes"][name]["name"])
                       for name in ("python", "uv")}}
        if (report.get("format") != "polaris.developer-id-signing/1"
                or report.get("release") != release_id or report.get("sourceRelease") != RELEASE_ID
                or report.get("signaturesVerified") is not True or report.get("artifacts") != expected):
            raise ValueError("Signed derivative evidence does not bind its exact artifacts.")
        signed_members = {key: item["artifact"] for key, item in report["nativeSignatures"].items()}
    elif any(key in manifest for key in ("signing", "compliance", "derivation")):
        raise ValueError("An upstream candidate cannot impersonate a signed derivative.")
    if {path.name for path in bundle_dir.iterdir()} != {path.name for path in paths}:
        raise ValueError("Bundle must have exactly the expected immutable artifacts.")
    package = inspect_payload(bundle_dir / "payload.tar.gz", manifest, signed_members=signed_members)
    if manifest.get("nativeCompatibility") != native_inventory(bundle_dir, manifest):
        raise ValueError("Native inventory is missing, changed or incompatible.")
    pins = {path.name: artifact(path) for path in paths}
    return manifest, pins, package


def build(*, bundle_dir: Path, source_archive: Path, output: Path,
          local_file: bool = False, base_url: str | None = None) -> dict[str, Any]:
    if local_file == (base_url is not None):
        raise ValueError("Choose explicit local-file mode or an approved HTTPS origin.")
    origin = https_origin(base_url) if base_url is not None else None
    bundle_dir, source_archive, output = map(regular_path, (bundle_dir, source_archive, output))
    if output.exists() or output.is_symlink():
        raise ValueError("Homebrew output must be a new immutable directory.")
    if output.is_relative_to(bundle_dir) or "theo-0.3.0-macos-arm64-r1" in output.parts:
        raise ValueError("Homebrew output must not modify a bundle or frozen artifact directory.")
    manifest, pins, package = inspect_bundle(bundle_dir)
    manifest_raw = read(bundle_dir / "manifest.json")
    manifest_pin = pins["manifest.json"]
    release_id = manifest["id"]
    archive_root = f"{release_id}-homebrew"
    source_pin = artifact(source_archive)
    inspect_source(source_archive, package)
    provenance = {
        "format": "polaris.homebrew-provenance/1", "release": release_id, "version": VERSION,
        "platform": PLATFORM, "bundle": pins, "source": source_pin,
        "packageValidated": False, "analyzerRuntime": "not_checked", "nativeHostVerified": False,
        "publicationPerformed": False,
    }
    output.mkdir(mode=0o700, parents=True)
    archive_path = output / f"{archive_root}.tar.gz"
    with archive_path.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            add_tar(archive, bundle_dir / manifest["runtimes"]["python"]["name"], {"python"},
                    links=True, archive_root=archive_root)
            add_tar(archive, bundle_dir / manifest["runtimes"]["uv"]["name"],
                    {"uv-aarch64-apple-darwin"}, rename_root="uv", links=True, archive_root=archive_root)
            add_tar(archive, bundle_dir / "payload.tar.gz", {"app", "analyzer"},
                    prefix="wheelhouse/", archive_root=archive_root)
            add_tar(archive, bundle_dir / "third-party-sources.tar.gz", {"third-party-sources"},
                    archive_root=archive_root)
            if "compliance" in manifest:
                add_tar(archive, bundle_dir / "compliance.tar.gz", {"compliance"}, archive_root=archive_root)
                add_file(archive, "signing-report.json", bundle_dir / "signing-report.json", archive_root=archive_root)
            add_bytes(archive, "manifest.json", manifest_raw, archive_root=archive_root)
            add_bytes(archive, "provenance.json", json_bytes(provenance), archive_root=archive_root)
            add_file(archive, f"source/theovex_polaris-{VERSION}.tar.gz", source_archive, archive_root=archive_root)
    for name, expected_pin in pins.items():
        verify(bundle_dir / name, expected_pin)
    verify(source_archive, source_pin)
    pin = artifact(archive_path)
    url = archive_path.as_uri() if local_file else f"{origin}/releases/{release_id}/{archive_path.name}"
    template = read(ROOT / "packaging/homebrew/polaris.rb").decode("utf-8")
    guard = 'raise "Generate a pinned candidate with scripts/build_homebrew_formula.py first." # @@GENERATOR_GUARD@@'
    marker = "  # @@ARTIFACT_DECLARATIONS@@"
    if template.count(guard) != 1 or template.count(marker) != 1:
        raise ValueError("Formula template is missing its generation boundary.")
    declarations = "\n".join((
        f"  url {json.dumps(url)}", f"  version {json.dumps(VERSION)}", f"  sha256 {json.dumps(pin['sha256'])}",
        f"  THEO_RELEASE = {json.dumps(release_id)}.freeze",
        f"  THEO_MANIFEST_SHA256 = {json.dumps(manifest_pin['sha256'])}.freeze",
    ))
    formula = template.replace(guard, "# Generated from inspected immutable artifacts; publication is not performed.")
    formula = formula.replace(marker, declarations)
    if "@@" in formula:
        raise ValueError("Formula contains an unresolved generation marker.")
    with (output / "polaris.rb").open("x") as stream:
        stream.write(formula)
    result = {
        "format": "polaris.homebrew-release/1", "release": release_id, "version": VERSION,
        "platform": PLATFORM, "availability": "unpublished", "downloadOrigin": None,
        "artifact": {**pin, "url": url}, "manifest": manifest_pin, "source": source_pin,
        "formula": artifact(output / "polaris.rb"), "mode": "local-file" if local_file else "https-origin",
        "installationValidated": False, "publicationPerformed": False,
    }
    with (output / "homebrew.json").open("xb") as stream:
        stream.write(json_bytes(result))
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid generator arguments; use --help and never supply credentials.")


def main() -> None:
    parser = Parser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local-file", action="store_true")
    source.add_argument("--base-url")
    try:
        arguments = parser.parse_args()
        result = build(bundle_dir=arguments.bundle_dir, source_archive=arguments.source_archive,
                       output=arguments.output, local_file=arguments.local_file, base_url=arguments.base_url)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit("Homebrew candidate not generated: artifact, identity, path or archive validation failed.") from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

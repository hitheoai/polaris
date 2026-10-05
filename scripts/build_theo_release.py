"""Assemble an UNPUBLISHED macOS-arm64 Theo candidate from inspected offline artifacts.

No hosting, publication, credentials, model files or source dependency builds are performed.
The lead supplies the public wheel, two separately resolved wheelhouses and pinned runtimes.
"""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import importlib.util
import json
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packaging" / "installer"
RELEASE_ID = "theo-0.3.3-macos-arm64-r1"
MINIMUM_MACOS = "15.0"
HOSTS = ["warp", "cursor", "claude-code", "codex", "vscode", "windsurf"]

def helper(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("release_" + name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Artifacts must be regular files, not symlinks.")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            value.update(chunk)
    return value.hexdigest()


def artifact(path: Path) -> dict[str, Any]:
    return {"name": path.name, "sha256": digest(path), "bytes": path.stat().st_size}


def normalized(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def constraints(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+", line):
            raise ValueError("Candidate constraints must pin one exact version per package.")
        name, version = line.split("==")
        if normalized(name) in result:
            raise ValueError("Duplicate candidate constraint.")
        result[normalized(name)] = version
    return result


def supported_tag(tag: str) -> bool:
    pieces = tag.split("-")
    if len(pieces) != 3:
        return False
    python, abi, platform = pieces
    python_ok = ("py3" in python.split(".") and abi == "none"
                 or python == "cp311" and abi in ("cp311", "abi3", "none")
                 or re.fullmatch(r"cp3(?:[6-9]|10)", python) is not None and abi == "abi3")
    platforms = platform.split(".")
    platform_ok = any(item == "any" or re.fullmatch(r"macosx_[0-9]+_[0-9]+_(arm64|universal2)", item)
                      for item in platforms)
    return bool(python_ok and platform_ok)


def wheel_metadata(path: Path) -> tuple[str, str]:
    digest(path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata = [name for name in names if name.count("/") == 1
                    and name.endswith(".dist-info/METADATA")]
        wheels = [name for name in names if name.count("/") == 1
                  and name.endswith(".dist-info/WHEEL")]
        if (len(metadata) != 1 or len(wheels) != 1
                or metadata[0].rsplit("/", 1)[0] != wheels[0].rsplit("/", 1)[0]):
            raise ValueError("A wheel lacks unambiguous metadata.")
        parser = email.parser.Parser()
        information = parser.parsestr(archive.read(metadata[0]).decode("utf-8"))
        tags = parser.parsestr(archive.read(wheels[0]).decode("utf-8")).get_all("Tag", [])
        if not any(supported_tag(tag) for tag in tags):
            raise ValueError("A wheel is not compatible with CPython 3.11 on macOS arm64.")
        name, version = information.get("Name"), information.get("Version")
        if not name or not version or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version):
            raise ValueError("A wheel lacks a valid name or pinned version.")
        for member in archive.infolist():
            parts = Path(member.filename).parts
            if (member.filename.startswith("/") or ".." in parts
                    or stat.S_ISLNK(member.external_attr >> 16)):
                raise ValueError("A wheel contains unsafe path or symlink entries.")
        return normalized(name), version


def check_public_wheel(path: Path, version: str) -> None:
    if wheel_metadata(path) != ("theovex-polaris", version):
        raise ValueError("The public wheel version must match this release.")
    spec = importlib.util.spec_from_file_location("theo_public_builder", ROOT / "scripts" / "build_public_wheel.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with zipfile.ZipFile(path) as archive:
        module.check_contents(archive.namelist(), "wheel")
        entries = [name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt")]
        if len(entries) != 1 or not all(entry in archive.read(entries[0]).decode() for entry in (
            "theo = polaris.onboarding.cli:main", "polaris = polaris.cli:main",
        )):
            raise ValueError("The public wheel is missing a required console entry point.")


def wheel_set(directory: Path, pins: dict[str, str], *, public_wheel: Path | None = None
              ) -> tuple[list[Path], dict[str, str]]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Wheelhouse must be a regular directory.")
    wheels = sorted(directory.glob("*.whl"))
    if public_wheel is not None:
        wheels = [*wheels, public_wheel]
    versions = {}
    for path in wheels:
        name, version = wheel_metadata(path)
        if name in versions:
            raise ValueError("Wheelhouse has duplicate distributions; supply exactly one compatible wheel each.")
        if pins.get(name) != version:
            raise ValueError(f"The candidate constraint does not permit {name} at this wheel's version.")
        versions[name] = version
    return wheels, versions


def validate_runtime(path: Path, pin: dict[str, Any], root: str) -> None:
    if artifact(path) != {key: pin[key] for key in ("name", "sha256", "bytes")}:
        raise ValueError("Runtime archive differs from its inspected upstream size or digest.")
    with tarfile.open(path, "r:gz") as archive:
        for item in archive:
            name = posixpath.normpath(item.name)
            if not (name == root or name.startswith(root + "/")) or item.name.startswith("/"):
                raise ValueError("Runtime archive escapes its private root.")
            if not (item.isdir() or item.isfile() or item.issym() or item.islnk()):
                raise ValueError("Runtime archive has a special file.")
            if item.issym() or item.islnk():
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), item.linkname)
                                           if item.issym() else item.linkname)
                if item.linkname.startswith("/") or not (target == root or target.startswith(root + "/")):
                    raise ValueError("Runtime archive has an escaping link.")


def payload_file(stage: Path, component: str, wheels: list[Path]) -> None:
    folder = stage / component / "wheels"
    folder.mkdir(parents=True)
    lines = []
    for source in wheels:
        name, version = wheel_metadata(source)
        shutil.copyfile(source, folder / source.name)
        lines.append(helper("analyzer_delivery").requirements_line(
            name, version, digest(source), component=component,
        ))
    (stage / component / "requirements.txt").write_text("\n".join(sorted(lines)) + "\n")


def deterministic_archive(stage: Path, target: Path) -> None:
    with target.open("xb") as output, gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in sorted(stage.rglob("*")):
                if not path.is_file():
                    continue
                info = tarfile.TarInfo(str(path.relative_to(stage)))
                info.size, info.mode, info.mtime = path.stat().st_size, 0o600, 0
                with path.open("rb") as stream:
                    archive.addfile(info, stream)


def native_inventory(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("theo_native", ROOT / "scripts/release_native.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inventory(bundle, manifest)


def render_bootstrap(output: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Render exact derived pins; never change an existing bootstrap or manifest."""
    pins, release_id = manifest["runtimes"], manifest["id"]
    manifest_pin = artifact(output / "manifest.json")
    installer_source = (INSTALLER / "install.py").read_text()
    original = f'RELEASE_ID = "{RELEASE_ID}"'
    if installer_source.splitlines().count(original) != 1:
        raise ValueError("Installer lacks its exact release-identity boundary.")
    installer_source = installer_source.replace(original, f'RELEASE_ID = "{release_id}"')
    substitutions = {
        "RELEASE_ID": release_id, "MANIFEST_SHA256": manifest_pin["sha256"],
        "MANIFEST_BYTES": str(manifest_pin["bytes"]), "INSTALLER_SOURCE": installer_source,
        **{f"{key.upper()}_{name.upper()}": str(pins[key][name])
           for key in ("uv", "python") for name in ("name", "sha256", "bytes")},
    }
    template = (INSTALLER / "install-theo.sh.in").read_text()
    for key, value in substitutions.items():
        template = template.replace(f"@@{key}@@", value)
    if re.search(r"@@[A-Z_]+@@", template):
        raise ValueError("An installer pin is unresolved.")
    bootstrap = output / "install-theo.sh"
    with bootstrap.open("x") as stream:
        stream.write(template)
    bootstrap.chmod(0o700)
    bootstrap_pin = artifact(bootstrap)
    release = {
        "format": "polaris.onboarding-release/1", "id": release_id, "version": manifest["version"],
        "minimumMacOS": MINIMUM_MACOS, "platform": "macos-arm64", "availability": "unpublished",
        "downloadOrigin": None, "apiOrigin": None,
        "bootstrap": {"path": f"/releases/{release_id}/install-theo.sh",
                      "sha256": bootstrap_pin["sha256"], "bytes": bootstrap_pin["bytes"]},
        "hosts": HOSTS,
    }
    with (output / "bootstrap.json").open("x") as stream:
        stream.write(json.dumps(release, indent=2) + "\n")
    return release


def build(*, wheel: Path, app_wheels: Path, analyzer_wheels: Path, runtime_dir: Path,
          source_packet: Path, source_manifest_sha256: str, output: Path) -> dict[str, Any]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    if version != "0.3.3":
        raise ValueError("Update the immutable release contract before building a different version.")
    check_public_wheel(wheel, version)
    pins = json.loads((INSTALLER / "runtime-pins.json").read_text())
    for component, archive_root in (("uv", "uv-aarch64-apple-darwin"), ("python", "python")):
        validate_runtime(runtime_dir / pins[component]["name"], pins[component], archive_root)
    app_files, app_versions = wheel_set(
        app_wheels, {**constraints(INSTALLER / "app-constraints.txt"), "theovex-polaris": version},
        public_wheel=wheel,
    )
    delivery = helper("analyzer_delivery")
    analyzer_files, analyzer_versions = delivery.validate_wheelhouse(analyzer_wheels)
    identity = delivery.identity().manifest_identity()
    delivery.validate_manifest({
        "analyzerIdentity": identity, "runtimes": pins,
        "environments": {"app": app_versions, "analyzer": analyzer_versions},
    })
    sources = helper("source_delivery")
    source_report = sources.qualifier().validate_source_packet(
        source_packet, expected_manifest_sha256=source_manifest_sha256,
    )
    if identity["derivativeWheelSha256"] not in source_report["artifactBindings"]:
        raise ValueError("Source packet does not bind the delivered analyzer derivative.")
    if output.exists() or output.is_symlink():
        raise ValueError("The immutable candidate destination must be new; existing releases are never replaced.")
    output.mkdir(parents=True, mode=0o700)
    source_pin = sources.build_archive(
        source_packet, source_manifest_sha256, output / sources.ARCHIVE_NAME,
    )
    with tempfile.TemporaryDirectory(prefix="theo-release-payload-") as temporary:
        stage = Path(temporary)
        payload_file(stage, "app", app_files)
        payload_file(stage, "analyzer", analyzer_files)
        deterministic_archive(stage, output / "payload.tar.gz")
    for component in ("uv", "python"):
        shutil.copyfile(runtime_dir / pins[component]["name"], output / pins[component]["name"])
    manifest = {
        "format": "polaris.theo-bundle/1", "id": RELEASE_ID, "version": version, "platform": "macos-arm64",
        "minimumMacOS": MINIMUM_MACOS,
        "availability": "unpublished", "downloadOrigin": None, "apiOrigin": None,
        "payload": artifact(output / "payload.tar.gz"), "runtimes": {key: pins[key] for key in ("uv", "python")},
        "environments": {"app": app_versions, "analyzer": analyzer_versions},
        "analyzerIdentity": identity, "thirdPartySources": source_pin,
        "hosts": HOSTS, "modelIncluded": False, "nativeHostVerified": False,
    }
    manifest["nativeCompatibility"] = native_inventory(output, manifest)
    with (output / "manifest.json").open("x") as stream:
        stream.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    release = render_bootstrap(output, manifest)
    return {"directory": str(output), "release": release, "installationValidated": False,
            "publicationPerformed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("wheel", "app-wheels", "analyzer-wheels", "runtime-dir", "source-packet", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = build(wheel=args.wheel.absolute(), app_wheels=args.app_wheels.absolute(),
                       analyzer_wheels=args.analyzer_wheels.absolute(), runtime_dir=args.runtime_dir.absolute(),
                       source_packet=args.source_packet.absolute(), source_manifest_sha256=args.source_manifest_sha256,
                       output=args.output.absolute())
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise SystemExit(f"Theo candidate not completed: {exc}") from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

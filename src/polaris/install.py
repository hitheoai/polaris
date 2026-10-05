"""Install and manage local Polaris models. Only `pull` uses the network, and only when asked.

Models live in ~/.polaris/models/<name>. `~/.polaris/models/current` is a small text file that
names the active model. Archives are checksummed, extracted safely, integrity-verified, and
self-tested on this machine before they become active.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from polaris.artifacts import read_manifest
from polaris.review.loader import polaris_home, resolve_model

MAX_ARCHIVE_BYTES = 3 * 1024**3
CHUNK = 1024 * 1024


class InstallError(RuntimeError):
    pass


def models_dir() -> Path:
    return polaris_home() / "models"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pack(bundle: Path, output: Path) -> dict[str, Any]:
    """Create `<name>.tar.gz` plus `<name>.tar.gz.sha256` from a verified bundle."""
    manifest = read_manifest(bundle)
    if output.exists():
        raise InstallError(f"{output} already exists")
    name = f"{manifest.model_version}"
    with tarfile.open(output, "w:gz", compresslevel=6) as archive:
        for path in sorted(bundle.rglob("*")):
            if path.is_symlink():
                raise InstallError("bundles must not contain symlinks")
            archive.add(path, arcname=f"{name}/{path.relative_to(bundle).as_posix()}", recursive=False)
    checksum = sha256_file(output)
    output.with_name(output.name + ".sha256").write_text(f"{checksum}  {output.name}\n", encoding="utf-8")
    return {"archive": str(output), "sha256": checksum, "bytes": output.stat().st_size, "model_version": name}


def _expected_checksum(archive: Path, sha256: str | None) -> str | None:
    if sha256:
        return sha256.strip().lower()
    sidecar = archive.with_name(archive.name + ".sha256")
    if sidecar.is_file():
        return sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
    return None


def install_archive(archive: Path, *, sha256: str | None = None, activate: bool = True,
                    device: str = "auto", require_checksum: bool = True) -> dict[str, Any]:
    """Verify, extract, integrity-check and self-test a model archive; optionally make it active."""
    if not archive.is_file():
        raise InstallError(f"{archive} not found")
    expected = _expected_checksum(archive, sha256)
    if expected is None and require_checksum:
        raise InstallError("no checksum: pass --sha256 or keep the .sha256 file next to the archive")
    actual = sha256_file(archive)
    if expected is not None and actual != expected:
        raise InstallError("checksum mismatch: the archive is damaged or not the published file")
    root = models_dir()
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root, prefix=".installing-") as temporary:
        staging = Path(temporary)
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise InstallError("archive contains links or special files")
            tops = {Path(member.name).parts[0] for member in members if member.name}
            if len(tops) != 1:
                raise InstallError("archive must contain exactly one model folder")
            tar.extractall(staging, filter="data")
        top = tops.pop()
        extracted = staging / top
        manifest = read_manifest(extracted)
        target = root / f"{manifest.model_version}-{manifest.model_digest[7:19]}"
        if target.exists():
            if read_manifest(target).model_digest != manifest.model_digest:
                raise InstallError(f"{target} exists with different contents")
        else:
            extracted.rename(target)
    report = check_model(target, device=device)
    if activate and report["loads"]:
        use(target)
    return {"installed": str(target), "sha256": actual, "active": activate and report["loads"], **report}


def pull(url: str, *, sha256: str | None = None, activate: bool = True, device: str = "auto") -> dict[str, Any]:
    """Download an archive over HTTPS, verify its checksum, then install it."""
    if not url.startswith("https://"):
        raise InstallError("only https:// model URLs are allowed")
    if sha256 is None:
        with urllib.request.urlopen(url + ".sha256", timeout=30) as response:  # noqa: S310 - https enforced
            sha256 = response.read(4096).decode("utf-8").split()[0]
    with tempfile.TemporaryDirectory(prefix="polaris-download-") as temporary:
        path = Path(temporary) / Path(url.split("?", 1)[0]).name
        received = 0
        with urllib.request.urlopen(url, timeout=60) as response, path.open("wb") as stream:  # noqa: S310
            while chunk := response.read(CHUNK):
                received += len(chunk)
                if received > MAX_ARCHIVE_BYTES:
                    raise InstallError("download is larger than any Polaris model should be")
                stream.write(chunk)
        return install_archive(path, sha256=sha256, activate=activate, device=device)


def use(target: Path) -> Path:
    """Make `target` (a model folder) the active model."""
    read_manifest(target)
    pointer = models_dir() / "current"
    if pointer.is_symlink() or pointer.is_dir():
        raise InstallError(f"{pointer} must be a plain file; remove it and try again")
    pointer.parent.mkdir(parents=True, exist_ok=True)
    temporary = pointer.with_name(".current.tmp")
    temporary.write_text(str(target.resolve()) + "\n", encoding="utf-8")
    temporary.replace(pointer)
    return target


def list_models() -> list[dict[str, Any]]:
    current = resolve_model()
    found = []
    for folder in sorted(models_dir().glob("*")) if models_dir().is_dir() else []:
        if not folder.is_dir() or folder.name.startswith(".") or folder.is_symlink():
            continue
        try:
            manifest = read_manifest(folder)
        except Exception:  # noqa: BLE001 - listed as damaged rather than crashing the listing
            found.append({"name": folder.name, "path": str(folder), "status": "damaged", "active": False})
            continue
        found.append({
            "name": folder.name, "path": str(folder), "model_version": manifest.model_version,
            "release_status": manifest.release_status, "supported_checks": manifest.supported_checks,
            "self_test": "selftest.json" in manifest.files,
            "active": current is not None and current.resolve() == folder.resolve(),
        })
    return found


def check_model(path: Path, *, device: str = "auto") -> dict[str, Any]:
    """Load a model on this machine, running its self-test when this runtime differs."""
    from polaris.errors import PolarisError
    from polaris.review.loader import auto_device
    from polaris.runtime import LocalBackend

    chosen = auto_device() if device == "auto" else device
    manifest = read_manifest(path)
    try:
        backend = LocalBackend(path, device=chosen, allow_experimental=True)
    except PolarisError as exc:
        return {"loads": False, "device": chosen, "error": exc.code, "model_version": manifest.model_version}
    return {
        "loads": True, "device": chosen, "model_version": manifest.model_version,
        "release_status": backend.identity.release_status, "runtime": backend.identity.runtime_variant,
        "runtime_verified_by_self_test": backend.runtime_verified, "self_test": backend.selftest_result,
    }


def describe(path: Path | None = None) -> dict[str, Any]:
    target = path or resolve_model()
    if target is None:
        return {"installed": False, "models_dir": str(models_dir())}
    manifest = read_manifest(target)
    info: dict[str, Any] = {
        "installed": True, "path": str(target), "model_version": manifest.model_version,
        "release_status": manifest.release_status, "supported_checks": manifest.supported_checks,
        "base_model": manifest.base_model, "calibrated_runtime": manifest.runtime_variant,
        "self_test": "selftest.json" in manifest.files,
    }
    card = target / "MODEL_CARD.txt"  # bundles only hold .json, .txt and .safetensors files
    if card.is_file():
        info["model_card"] = str(card)
    notes = target / "release.json"
    if notes.is_file():
        info["release"] = json.loads(notes.read_text(encoding="utf-8"))
    return info


def remove(target: Path) -> None:
    """Delete an installed model folder (never the active one)."""
    current = resolve_model()
    if current is not None and current.resolve() == target.resolve():
        raise InstallError("switch to another model before removing the active one")
    if target.resolve().parent != models_dir().resolve():
        raise InstallError("only folders inside the Polaris models directory can be removed")
    shutil.rmtree(target)

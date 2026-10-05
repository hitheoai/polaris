"""Prepare approved immutable hosting files, without uploading, tagging or changing availability."""

from __future__ import annotations

import argparse
import functools
import importlib.util
import json
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
GATES = frozenset({
    "source_tests", "standalone_lifecycle", "homebrew_lifecycle", "minimum_macos_15",
    "clean_account", "second_apple_silicon_mac", "quarantined_download", "native_editor_invocation",
    "license_source_advisory_approval", "publisher_origin_ownership",
})


@functools.lru_cache
def acceptance_tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "publication_acceptance", ROOT / "scripts/collect_release_acceptance.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_tool() -> Any:
    spec = importlib.util.spec_from_file_location("publication_macos", ROOT / "scripts/macos_release.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def set_digest(artifacts: dict[str, Any]) -> str:
    return str(acceptance_tool().set_digest(artifacts))


def acceptance(directory: Path, artifacts: dict[str, Any], *, helper: Any,
               config: dict[str, Any] | None = None) -> dict[str, Any]:
    if config is None:
        raise ValueError("Publication requires acceptance approval outside the collected evidence.")
    report = acceptance_tool().verify_report(
        directory, artifacts, helper=helper, require_complete=True,
        approval=config.get("acceptanceApproval"), source_revision=config["sourceRevision"],
        publisher=config,
    )
    return report


def build(bundle: Path, dmg_dir: Path, homebrew: Path, public: Path, acceptance_dir: Path,
          config_path: Path, output: Path, *, approved: bool = False) -> dict[str, Any]:
    if not approved:
        raise ValueError("Explicit --approve-release is required even for a local publication kit.")
    macos = release_tool()
    helper = macos.helpers()
    bundle, dmg_dir, homebrew, public, acceptance_dir = map(
        helper.regular_path, (bundle, dmg_dir, homebrew, public, acceptance_dir),
    )
    config_path = helper.regular_path(config_path)
    if config_path.is_relative_to(acceptance_dir):
        raise ValueError("Publisher approval must be supplied outside the evaluated acceptance evidence.")
    config = macos.configuration(config_path)
    signed = macos.verify_signed(bundle, config)
    manifest, _, package = helper.inspect_bundle(bundle)
    source = public / f"theovex_polaris-{helper.VERSION}.tar.gz"
    wheel = public / f"theovex_polaris-{helper.VERSION}-py3-none-any.whl"
    helper.inspect_source(source, package)
    _, wheel_version, wheel_package = helper.wheel_identity(helper.read(wheel, limit=250_000_000))
    if wheel_version != helper.VERSION or wheel_package != package:
        raise ValueError("Public wheel, source and signed bundle disagree.")
    dmg = json.loads(helper.read(dmg_dir / "result.json", limit=20_000_000))
    if (dmg.get("format") != "polaris.macos-distribution/1" or dmg.get("bundle") != signed["bundle"]
            or dmg.get("stapled") is not True or dmg.get("signatureVerified") is not True
            or dmg.get("notarization", {}).get("status") != "Accepted"
            or dmg.get("source") != helper.artifact(source)
            or dmg.get("artifact", {}).get("name") != f"{helper.SIGNED_RELEASE_ID}.dmg"):
        raise ValueError("A verified notarized and stapled DMG of these exact bytes is required.")
    image = dmg_dir / dmg["artifact"]["name"]
    helper.verify(image, dmg["artifact"])
    macos.verify_signature(image, config, native=False)
    macos.tool(["/usr/bin/xcrun", "stapler", "validate", str(image)])
    if macos.verify_distribution_contents(image, bundle, source) != dmg.get("content"):
        raise ValueError("DMG contents differ from the distribution evidence.")
    brew = json.loads(helper.read(homebrew / "homebrew.json"))
    archive_name = f"{helper.SIGNED_RELEASE_ID}-homebrew.tar.gz"
    url = f"{config['downloadOrigin'].rstrip('/')}/releases/{helper.SIGNED_RELEASE_ID}/{archive_name}"
    if (brew.get("format") != "polaris.homebrew-release/1" or brew.get("release") != helper.SIGNED_RELEASE_ID
            or brew.get("mode") != "https-origin" or brew.get("artifact", {}).get("name") != archive_name
            or brew.get("artifact", {}).get("url") != url
            or brew.get("manifest") != signed["bundle"]["manifest.json"]
            or brew.get("source") != helper.artifact(source)):
        raise ValueError("Homebrew requires the exact signed bundle and approved immutable HTTPS origin.")
    helper.verify(homebrew / archive_name, brew["artifact"])
    helper.verify(homebrew / "polaris.rb", brew["formula"])
    # Metadata alone can be rewritten to claim an unrelated archive/formula belongs to the
    # signed bundle. Rebuild the deterministic derivative from the inspected inputs.
    with tempfile.TemporaryDirectory(prefix="polaris-homebrew-verification-") as temporary:
        expected_brew = helper.build(
            bundle_dir=bundle, source_archive=source, output=Path(temporary).resolve() / "homebrew",
            base_url=config["downloadOrigin"],
        )
    if brew != expected_brew:
        raise ValueError("Homebrew bytes or formula differ from the approved signed-bundle derivative.")
    sources = acceptance_tool().distribution_sources(
        bundle, dmg_dir, homebrew, public, signed["bundle"], helper,
    )
    artifacts = {name: helper.artifact(path) for name, path in sources.items()}
    acceptance_pin = helper.artifact(acceptance_dir / "acceptance.json")
    acceptance(acceptance_dir, artifacts, helper=helper, config=config)
    output = macos.new_directory(output, bundle, dmg_dir, homebrew, public, acceptance_dir)
    for name, source_path in sources.items():
        helper.verify(source_path, artifacts[name])
        destination = output / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination)
        helper.verify(destination, artifacts[name])
    acceptance(acceptance_dir, artifacts, helper=helper, config=config)
    helper.verify(acceptance_dir / "acceptance.json", acceptance_pin)
    result = {"format": "polaris.publication-kit/1", "release": manifest["id"],
              "publisherRepository": config["publisherRepository"], "downloadOrigin": config["downloadOrigin"],
              "sourceRevision": config["sourceRevision"], "artifacts": artifacts,
              "artifactSetSha256": set_digest(artifacts), "acceptance": acceptance_pin,
              "reviewer": config["acceptanceApproval"]["reviewer"],
              "availability": "unpublished", "publicationPerformed": False,
              "localEvidenceOnly": True, "trustedCIBuildProvenance": False,
              "anonymousProductionDelivery": "not_verified", "redirectsPermitted": False}
    macos.write_json(output / "publication.json", result)
    with (output / "SHA256SUMS").open("x") as stream:
        stream.writelines(f"{pin['sha256']}  {name}\n" for name, pin in sorted(artifacts.items()))
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid publication arguments; use --help and never supply credentials.")


def main() -> None:
    parser = Parser(description=__doc__)
    for name in ("bundle-dir", "dmg-dir", "homebrew-dir", "public-dir", "acceptance-dir", "config", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--approve-release", action="store_true")
    try:
        args = parser.parse_args()
        result = build(args.bundle_dir, args.dmg_dir, args.homebrew_dir, args.public_dir,
                       args.acceptance_dir, args.config, args.output, approved=args.approve_release)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit("Publication preparation blocked by invalid, unapproved or incomplete release evidence.") from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

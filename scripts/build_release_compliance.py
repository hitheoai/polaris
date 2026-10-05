"""Build bounded, deterministic, OFFLINE release-input compliance evidence.

Never imports package code, executes tools, fetches URLs or extracts archive paths.
All copied materials are data-only. Collection is never authorization: /2 observations
require separate replay and independently authorized decisions before signing.
"""

from __future__ import annotations

import argparse
import base64
import collections
import csv
import datetime
import email.parser
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import struct
import tarfile
import tomllib
import unicodedata
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "packaging/compliance/policy.json"
MAX_FILE = 256 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_METADATA = 4 * 1024 * 1024
TOOL_FILES = (
    "scripts/build_release_compliance.py",
    "scripts/release_compliance_resolution.py",
    "packaging/compliance/resolution.schema.json",
)
HEX = re.compile(r"[a-f0-9]{64}")
NOTICE = re.compile(r"^(?:licen[sc]e|copying|copyright|notice|third[-_.]?party)(?:$|[-_.])", re.I)
MACHO = {bytes.fromhex(x) for x in (
    "cffaedfe", "cefaedfe", "feedfacf", "feedface",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
)}


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key.")
        result[key] = value
    return result


def parse_json(data: bytes, *, maximum: int = MAX_METADATA) -> Any:
    require(len(data) <= maximum, "JSON exceeds the metadata bound.")
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=lambda _: require(False, "Non-finite JSON value."))


def canonical(path: Path) -> Path:
    path = path.absolute()
    require(path == path.resolve(), "Filesystem paths must be canonical and contain no symlinks.")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Linked filesystem path.")
    return path


def read_regular(path: Path, maximum: int = MAX_FILE) -> bytes:
    canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Expected a regular input file.")
        require(info.st_size <= maximum, "Input exceeds its size bound.")
        data = stream.read(maximum + 1)
        require(len(data) == info.st_size and len(data) <= maximum, "Input changed while reading.")
        return data


def member_path(name: str, *, directory: bool = False) -> str:
    require(isinstance(name, str) and 0 < len(name) <= 1024, "Invalid archive path.")
    clean = name[:-1] if directory and name.endswith("/") else name
    require(not any(ord(c) < 32 or ord(c) == 127 for c in clean), "Control character in archive path.")
    require("\\" not in clean and ":" not in clean, "Nonportable archive path.")
    parts = clean.split("/")
    require(len(parts) <= 64 and all(p not in ("", ".", "..") for p in parts), "Escaping archive path.")
    require(unicodedata.normalize("NFC", clean) == clean, "Noncanonical Unicode archive path.")
    require(str(PurePosixPath(clean)) == clean and not clean.startswith("/"), "Absolute archive path.")
    return clean


def normalized(name: Any) -> str:
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is not None,
            "Invalid distribution name.")
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_version(value: Any) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}", value) is not None,
            "Invalid pinned version.")
    return value


def https_url(value: str) -> str:
    require(isinstance(value, str) and len(value) <= 4096 and not any(ord(c) < 33 for c in value),
            "Invalid evidence URL.")
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None
            and parsed.password is None and not parsed.fragment and "\\" not in value,
            "Evidence URLs must be credential-free HTTPS URLs.")
    require(re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname or "") is not None, "Invalid evidence host.")
    require(parsed.port in (None, 443), "Unexpected evidence port.")
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    require(all(k in {"recursive", "page", "per_page"} and all(v.isdigit() for v in values)
                for k, values in query.items()), "Unexpected evidence URL query.")
    return value


def pin(data: bytes, name: str) -> dict[str, Any]:
    return {"name": name, "bytes": len(data), "sha256": sha(data)}


def check_pin(data: bytes, record: dict[str, Any]) -> None:
    require(isinstance(record, dict) and type(record.get("bytes")) is int
            and isinstance(record.get("sha256"), str) and HEX.fullmatch(record["sha256"]) is not None,
            "Invalid artifact pin.")
    require(record["bytes"] == len(data) and record["sha256"] == sha(data), "Artifact pin mismatch.")


def archive_entries(data: bytes, *, wheel: bool = False) -> list[tuple[str, bytes | None, str | None]]:
    """Read bounded members; symlinks are recorded, never followed or written."""
    entries: list[tuple[str, bytes | None, str | None]] = []
    kinds: dict[str, str] = {}
    folded: set[str] = set()
    path_spellings: dict[str, str] = {}
    total = 0

    def accept(name: str, size: int, kind: str) -> str:
        nonlocal total
        name = member_path(name, directory=kind == "directory")
        require(name.casefold() not in folded, "Duplicate or case-colliding archive path.")
        for path in (name, *(str(p) for p in PurePosixPath(name).parents if str(p) != ".")):
            require(path_spellings.setdefault(path.casefold(), path) == path,
                    "Case-colliding archive directory.")
        require(len(kinds) < MAX_MEMBERS and 0 <= size <= MAX_FILE, "Archive member bound exceeded.")
        total += size
        require(total <= MAX_EXPANDED, "Expanded archive bound exceeded.")
        kinds[name] = kind
        folded.add(name.casefold())
        return name

    if wheel:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for item in archive.infolist():
                mode = item.external_attr >> 16
                require(not item.flag_bits & 1 and not stat.S_ISLNK(mode), "Encrypted or linked wheel entry.")
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "Special wheel entry.")
                kind = "directory" if item.is_dir() else "file"
                name = accept(item.filename, item.file_size, kind)
                if kind == "file":
                    content = archive.read(item)
                    require(len(content) == item.file_size, "Truncated wheel entry.")
                    entries.append((name, content, None))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar_archive:
            for member in tar_archive:
                require(not member.sparse and not member.mode & 0o6000, "Sparse or privileged archive entry.")
                require(member.isfile() or member.isdir() or member.issym() or member.islnk(), "Special tar entry.")
                kind = ("file" if member.isfile() else "directory" if member.isdir() else
                        "symlink" if member.issym() else "hardlink")
                name = accept(member.name, member.size, kind)
                if kind == "file":
                    stream = tar_archive.extractfile(member)
                    require(stream is not None, "Missing archive entry.")
                    assert stream is not None
                    with stream:
                        content = stream.read(MAX_FILE + 1)
                    require(len(content) == member.size, "Truncated archive entry.")
                    entries.append((name, content, None))
                elif kind in ("symlink", "hardlink"):
                    target = member.linkname
                    require(target and not target.startswith("/") and "\\" not in target
                            and not any(ord(c) < 32 for c in target), "Unsafe archive link.")
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target)
                                                 if kind == "symlink" else target)
                    member_path(resolved)
                    require(resolved.split("/")[0] == name.split("/")[0], "Escaping archive link.")
                    entries.append((name, None, resolved))
    folded_kinds = {name.casefold(): kind for name, kind in kinds.items()}
    links = {n: t for n, _, t in entries if t is not None}
    for name, _, link_target in entries:
        require(all(folded_kinds.get(str(parent).casefold()) not in ("file", "symlink", "hardlink")
                    for parent in PurePosixPath(name).parents if str(parent) != "."),
                "Archive entry has a nondirectory ancestor.")
        if link_target is not None:
            target = link_target
            visited = {name}
            while target in links:
                require(target not in visited, "Cyclic archive link.")
                visited.add(target)
                target = links[target]
            require(target in kinds or any(p.startswith(target + "/") for p in kinds),
                    "Dangling archive link.")
    return entries


def metadata(data: bytes) -> dict[str, Any]:
    require(len(data) <= MAX_METADATA, "Distribution metadata exceeds its bound.")
    value = email.parser.Parser().parsestr(data.decode("utf-8"))
    for field in ("Name", "Version", "License", "License-Expression"):
        require(len(value.get_all(field, [])) <= 1, "Ambiguous distribution metadata.")
    name, version = value.get("Name"), value.get("Version")
    require(bool(name and version), "Distribution metadata lacks name/version.")
    return {"name": normalized(name), "version": exact_version(version),
            "declaredLicense": value.get("License-Expression") or value.get("License"),
            "licenseFilesDeclared": value.get_all("License-File", []),
            "licenseClassifiers": [v for v in value.get_all("Classifier", []) if v.startswith("License ::")]}


def is_notice(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(NOTICE.match(p.name)) and p.suffix.lower() not in (".py", ".pyc", ".pyo", ".json")


def binary_format(data: bytes) -> str | None:
    if data[:4] in MACHO:
        if data[:4] in {bytes.fromhex(x) for x in ("cafebabe", "bebafeca", "cafebabf", "bfbafeca")}:
            endian = ">" if data[0] == 0xca else "<"
            if len(data) < 28 or not 0 < struct.unpack_from(endian + "I", data, 4)[0] <= 32:
                return None  # Java class magic is not itself a valid fat Mach-O header.
        return "Mach-O"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"!<arch>\n"):
        return "static-archive"
    if data.startswith(b"MZ") and len(data) >= 64:
        offset = struct.unpack_from("<I", data, 60)[0]
        if data[offset:offset + 4] == b"PE\0\0":
            return "PE"
    return None


class Inventory:
    def __init__(self) -> None:
        self.components: list[dict[str, Any]] = []
        self.component_ids: set[str] = set()
        self.files: list[dict[str, Any]] = []
        self.notices: dict[str, bytes] = {}
        self.vendor_manifests: list[dict[str, Any]] = []
        self.outer: list[dict[str, Any]] = []
        self.advisories: list[dict[str, Any]] = []
        self.total = 0

    def component(self, kind: str, location: str, content: bytes, *, name: str,
                  version: str | None = None, parent: str | None = None,
                  details: dict[str, Any] | None = None) -> dict[str, Any]:
        item = {"id": "component-" + sha(json_bytes([kind, location, sha(content)])),
                "kind": kind, "location": location, "name": name, "version": version,
                "sha256": sha(content), "bytes": len(content), "parent": parent, "notices": [],
                "hashScope": ("metadata" if kind in ("installed-distribution", "vendored-distribution")
                              else "declaration" if kind in ("vendored-declaration", "cargo-declaration")
                              else "supplied-file"),
                **(details or {})}
        require(item["id"] not in self.component_ids, "Duplicate inventory component.")
        self.component_ids.add(item["id"])
        self.components.append(item)
        return item

    def notice(self, component: dict[str, Any], location: str, data: bytes) -> None:
        require(len(data) <= MAX_METADATA and b"\0" not in data, "Invalid notice text.")
        data.decode("utf-8")
        digest = sha(data)
        self.notices[digest] = data
        component["notices"].append({"location": location, "sha256": digest,
                                     "path": f"licenses/{digest}.txt"})

    def scan(self, entries: list[tuple[str, bytes | None, str | None]], owner: dict[str, Any],
             *, depth: int = 0) -> None:
        require(depth <= 3, "Nested archive depth exceeded.")
        metadata_owners = {}
        for name, content, _ in entries:
            if content is not None and (name.endswith(".dist-info/METADATA")
                                        or name.endswith(".egg-info/PKG-INFO")):
                if owner["kind"] in ("wheel", "ensurepip-wheel") and name.count("/") == 1:
                    metadata_owners[name.rsplit("/", 1)[0]] = owner
                else:
                    details = metadata(content)
                    item = self.component(
                        "vendored-distribution" if "/_vendor/" in name else "installed-distribution",
                        owner["location"] + "!" + name, content, parent=owner["id"],
                        name=details["name"], version=details["version"],
                        details={k: v for k, v in details.items() if k not in ("name", "version")},
                    )
                    metadata_owners[name.rsplit("/", 1)[0]] = item
        for name, content, target in entries:
            location = owner["location"] + "!" + name
            if content is None:
                self.files.append({"location": location, "kind": "link", "target": target, "parent": owner["id"]})
                continue
            self.total += len(content)
            require(self.total <= 3 * MAX_EXPANDED and len(self.files) < MAX_MEMBERS,
                    "Cumulative inventory bound exceeded.")
            self.files.append({"location": location, "sha256": sha(content), "bytes": len(content),
                               "kind": "file", "parent": owner["id"]})
            if is_notice(name):
                matches = [(p, item) for p, item in metadata_owners.items() if name.startswith(p + "/")]
                self.notice(max(matches, key=lambda value: len(value[0]))[1] if matches else owner,
                            location, content)
            if content[:4] in MACHO or binary_format(content):
                fmt = binary_format(content)
                if fmt:
                    self.component("native-file", location, content, name=PurePosixPath(name).name,
                                   parent=owner["id"], details={"binaryFormat": fmt,
                                   "buildProvenance": "unresolved", "architectureInspection": "not_performed"})
            if name.endswith(".whl"):
                require(depth < 3, "Nested wheel depth exceeded.")
                self.wheel(content, location, "ensurepip-wheel", owner["id"], depth + 1)
            if PurePosixPath(name).name in ("vendor.txt", "vendored.txt"):
                require(len(content) <= MAX_METADATA, "Vendor manifest exceeds its bound.")
                lines = content.decode("utf-8").splitlines()
                unknown = []
                for line in lines:
                    value = line.split("#", 1)[0].strip()
                    if not value:
                        continue
                    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+!-]+)", value)
                    if match:
                        self.component("vendored-declaration", location + "#" + normalized(match[1]),
                                       value.encode(), name=normalized(match[1]), version=exact_version(match[2]),
                                       parent=owner["id"], details={"declarationOnly": True})
                    else:
                        unknown.append(value)
                self.vendor_manifests.append({"location": location, "sha256": sha(content),
                                              "unresolvedDeclarations": unknown})

    def wheel(self, data: bytes, location: str, kind: str, parent: str | None = None,
              depth: int = 0) -> dict[str, Any]:
        entries = archive_entries(data, wheel=True)
        files = {name: content for name, content, _ in entries if content is not None}
        descriptions = [n for n in files if n.count("/") == 1 and n.endswith(".dist-info/METADATA")]
        wheels = [n for n in files if n.count("/") == 1 and n.endswith(".dist-info/WHEEL")]
        require(len(descriptions) == len(wheels) == 1 and
                descriptions[0].rsplit("/", 1)[0] == wheels[0].rsplit("/", 1)[0],
                "Wheel metadata is missing or ambiguous.")
        details = metadata(files[descriptions[0]])
        filename = location.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        parts = filename.removesuffix(".whl").split("-")
        require(len(parts) in (5, 6) and normalized(parts[0]) == details["name"]
                and parts[1] == details["version"], "Wheel filename/metadata mismatch.")
        description = email.parser.Parser().parsestr(files[wheels[0]].decode("utf-8"))
        tags = description.get_all("Tag", [])
        require(bool(tags) and all(re.fullmatch(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", t)
                                  for t in tags), "Invalid wheel tags.")
        record_name = descriptions[0].rsplit("/", 1)[0] + "/RECORD"
        require(record_name in files, "Wheel RECORD is missing.")
        seen = set()
        for row in csv.reader(io.StringIO(files[record_name].decode("utf-8"))):
            require(len(row) == 3, "Invalid wheel RECORD row.")
            path, encoded, size = row
            member_path(path)
            require(path not in seen and path in files, "Wheel RECORD path is missing or duplicated.")
            seen.add(path)
            if path == record_name:
                require(encoded == size == "", "Wheel RECORD must not hash itself.")
                continue
            algorithm, separator, digest = encoded.partition("=")
            require(separator == "=" and algorithm in ("sha256", "sha384", "sha512")
                    and size.isdigit() and int(size) == len(files[path]), "Invalid wheel RECORD digest/size.")
            observed = base64.urlsafe_b64encode(hashlib.new(algorithm, files[path]).digest()).decode().rstrip("=")
            require(digest == observed, "Wheel RECORD digest mismatch.")
        signatures = {record_name + ".jws", record_name + ".p7s"}
        require(set(files) - signatures == seen - signatures, "Wheel RECORD coverage is incomplete.")
        item = self.component(kind, location, data, parent=parent, details={"tags": sorted(tags),
                              **{k: v for k, v in details.items() if k not in ("name", "version")}},
                              name=details["name"], version=details["version"])
        self.scan(entries, item, depth=depth)
        return item


def load_bundle(folder: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    folder = canonical(folder)
    require(folder.is_dir(), "Bundle directory is missing.")
    data = {p.name: read_regular(p) for p in sorted(folder.iterdir())}
    require("manifest.json" in data and "bootstrap.json" in data, "Bundle control files are missing.")
    manifest = parse_json(data["manifest.json"])
    require(isinstance(manifest, dict) and manifest.get("format") in
            ("polaris.theo-bundle/1", "polaris.theo-bundle/2"), "Unsupported bundle schema.")
    exact_version(manifest["version"])
    require(isinstance(manifest.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", manifest["id"]),
            "Invalid release identity.")
    require(manifest.get("modelIncluded") is False, "This compliance scope requires a no-model bundle.")
    require(set(manifest["runtimes"]) == {"python", "uv"}
            and set(manifest["environments"]) == {"app", "analyzer"}, "Unexpected bundle environments.")
    required = {"manifest.json", "bootstrap.json", "install-theo.sh"}
    artifacts = [manifest["payload"], *manifest["runtimes"].values()]
    if "thirdPartySources" in manifest:
        require(manifest["thirdPartySources"].get("name") == "third-party-sources.tar.gz",
                "Source packet requires its recipient-facing archive name.")
        artifacts.append(manifest["thirdPartySources"])
    for item in artifacts:
        name = member_path(item["name"])
        require("/" not in name and name not in required, "Ambiguous artifact name.")
        required.add(name)
        require(name in data, "Pinned artifact is missing.")
        check_pin(data[name], item)
        if item.get("url") is not None:
            https_url(item["url"])
    require(set(data) == required, "Expected exactly the manifest-bound bundle input contract.")
    bootstrap = parse_json(data["bootstrap.json"])
    require(all(bootstrap.get(k) == manifest.get(k) for k in ("id", "version", "platform")),
            "Bootstrap/release identity mismatch.")
    check_pin(data["install-theo.sh"], bootstrap["bootstrap"])
    match = re.search(rb"(?m)^MANIFEST_SHA256=['\"]([a-f0-9]{64})['\"]$", data["install-theo.sh"])
    require(match is not None and match[1].decode() == sha(data["manifest.json"]), "Installer manifest binding mismatch.")
    return data, manifest


def collect_bundle(data: dict[str, bytes], manifest: dict[str, Any]) -> Inventory:
    inventory = Inventory()
    payload = manifest["payload"]["name"]
    entries = archive_entries(data[payload])
    requirements: dict[str, dict[str, tuple[str, str]]] = {}
    for component in ("app", "analyzer"):
        matches = [content for name, content, _ in entries if name == f"{component}/requirements.txt"]
        require(len(matches) == 1 and matches[0] is not None, "Requirements are missing or ambiguous.")
        assert matches[0] is not None
        pins = {}
        for line in matches[0].decode("utf-8").splitlines():
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[(?:mcp|crypto)\])?==([A-Za-z0-9_.+!-]+) --hash=sha256:([a-f0-9]{64})", line)
            require(match is not None, "Requirements must be exact hash-locked pins.")
            assert match is not None
            name = normalized(match[1])
            require(name not in pins, "Duplicate requirement.")
            pins[name] = (exact_version(match[2]), match[3])
        requirements[component] = pins
    observed: dict[str, dict[str, str]] = {"app": {}, "analyzer": {}}
    for name, content, target in entries:
        require(content is not None and target is None, "Payload must contain only regular files.")
        assert content is not None
        if name in ("app/requirements.txt", "analyzer/requirements.txt"):
            continue
        parts = name.split("/")
        require(len(parts) == 3 and parts[0] in observed and parts[1] == "wheels"
                and parts[2].endswith(".whl"), "Unexpected payload member.")
        item = inventory.wheel(content, payload + "!" + name, "wheel")
        component, package, version = parts[0], item["name"], item["version"]
        require(package not in observed[component], "Duplicate wheel distribution.")
        require(requirements[component].get(package) == (version, sha(content)), "Wheel requirement mismatch.")
        observed[component][package] = version
        inventory.outer.append({"environment": component, **item})
    for component in observed:
        require(observed[component] == manifest["environments"][component]
                and set(observed[component]) == set(requirements[component]), "Manifest inventory mismatch.")
    require(observed["app"].get("theovex-polaris") == manifest["version"], "Public package/release version mismatch.")
    for name, record in sorted(manifest["runtimes"].items()):
        content = data[record["name"]]
        item = inventory.component("runtime", record["name"], content, name=name,
                                   version=exact_version(record["version"]),
                                   details={"upstreamURL": record.get("url"),
                                            "suppliedProvenance": record.get("upstream")})
        inventory.scan(archive_entries(content), item)
    return inventory


def load_supplements(folder: Path | None) -> tuple[list[dict[str, Any]], dict[str, bytes], dict[str, str]]:
    if folder is None:
        return [], {}, {}
    folder = canonical(folder)
    raw = read_regular(folder / "evidence.json", MAX_METADATA)
    value = parse_json(raw)
    require(isinstance(value, dict) and value.get("format") == "polaris.compliance-evidence/1"
            and isinstance(value.get("records"), list), "Invalid supplements schema.")
    require(len(value["records"]) <= 20_000, "Too many evidence records.")
    records, blobs = [], {}
    inputs = {"evidence.json": sha(raw)}
    ids = set()
    for item in value["records"]:
        require(isinstance(item, dict) and set(item) <= {
            "id", "kind", "subject", "url", "revision", "retrievedAt", "status", "reason",
            "file", "bytes", "sha256", "format", "requestSha256", "requestFile", "queryIndex",
            "review", "upstreamPath",
        }, "Unknown supplement fields.")
        require(isinstance(item.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", item["id"])
                and item["id"] not in ids, "Duplicate or invalid evidence ID.")
        ids.add(item["id"])
        require(item.get("kind") in {"license", "source", "source-manifest", "build-metadata",
                                    "dependency-lock", "advisory", "registry-metadata"},
                "Unknown evidence purpose.")
        require(item.get("status") in {"retrieved", "unavailable", "unknown"}, "Invalid evidence status.")
        require(isinstance(item.get("retrievedAt"), str) and
                re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|\+00:00)", item["retrievedAt"]),
                "Evidence acquisition time is missing.")
        acquired = datetime.datetime.fromisoformat(item["retrievedAt"].replace("Z", "+00:00"))
        require(acquired.utcoffset() == datetime.timedelta(0), "Evidence acquisition time must be UTC.")
        https_url(item["url"])
        subject = item.get("subject")
        require(isinstance(subject, dict) and set(subject) <= {"name", "version", "ecosystem", "sha256"}
                and set(subject) >= {"name", "version", "sha256"}, "Evidence subject must bind name/version/hash.")
        normalized(subject["name"])
        exact_version(subject["version"])
        require(isinstance(subject["sha256"], str) and HEX.fullmatch(subject["sha256"]) is not None,
                "Evidence subject hash is missing.")
        require(subject.get("ecosystem") in (None, "PyPI", "crates.io"), "Unsupported evidence ecosystem.")
        if item["status"] == "retrieved":
            name = member_path(item["file"])
            content = read_regular(folder / name)
            check_pin(content, item)
            inputs[name] = sha(content)
            if item["kind"] == "license":
                require(len(content) <= MAX_METADATA and b"\0" not in content, "Invalid supplemental license.")
                content.decode("utf-8")
            if item["kind"] == "source" and name.endswith((".tar.gz", ".whl", ".zip")):
                archive_entries(content, wheel=name.endswith((".whl", ".zip")))
            blobs[sha(content)] = content
            if item["kind"] == "advisory" and item.get("format") == "osv-querybatch":
                request_name = member_path(item["requestFile"])
                request = read_regular(folder / request_name, MAX_METADATA)
                require(sha(request) == item.get("requestSha256"), "Advisory request hash mismatch.")
                inputs[request_name] = sha(request)
                blobs[sha(request)] = request
        else:
            require(not any(k in item for k in ("file", "sha256", "bytes", "requestFile", "requestSha256")),
                    "Unavailable evidence must not pretend to contain verified bytes.")
        records.append(dict(item))
    return sorted(records, key=lambda r: r["id"]), blobs, inputs


def apply_supplements(inventory: Inventory, records: list[dict[str, Any]],
                      blobs: dict[str, bytes]) -> None:
    for record in sorted(records, key=lambda r: (r["kind"] != "dependency-lock", r["id"])):
        subject = record["subject"]
        matched = [c for c in inventory.components if c["name"] == subject["name"]
                   and c["version"] == subject["version"] and c["sha256"] == subject["sha256"]]
        require(bool(matched), "Supplement does not match an actual component's name/version/hash.")
        if record["status"] != "retrieved":
            continue
        data = blobs[record["sha256"]]
        if record["kind"] == "license":
            for item in matched:
                inventory.notice(item, "supplement:" + record["id"], data)
        elif record["kind"] == "dependency-lock":
            require(record.get("format") == "cargo-lock", "Unsupported dependency-lock evidence.")
            lock = tomllib.loads(data.decode("utf-8"))
            require(isinstance(lock.get("package"), list) and len(lock["package"]) <= 10_000,
                    "Invalid Cargo dependency lock.")
            for entry in lock["package"]:
                require(isinstance(entry.get("name"), str) and
                        re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}", entry["name"]),
                        "Invalid Cargo package name.")
                name, version = entry["name"], exact_version(entry["version"])
                source = entry.get("source")
                if entry.get("checksum") is not None:
                    require(HEX.fullmatch(entry["checksum"]) is not None, "Invalid Cargo package checksum.")
                inventory.component("cargo-declaration", "supplement:" + record["id"] + "!" + name + "@" + version,
                                    json_bytes(entry), name=name, version=version, parent=matched[0]["id"],
                                    details={"declarationOnly": True, "source": source,
                                             "registryChecksum": entry.get("checksum"),
                                             "compiledIntoArtifact": "unverified"})
        elif record["kind"] == "advisory":
            expected_ecosystem = "crates.io" if all(c["kind"] == "cargo-declaration" for c in matched) else "PyPI"
            require(subject.get("ecosystem", "PyPI") == expected_ecosystem,
                    "Advisory ecosystem does not match the component.")
            inventory.advisories.append(advisory_result(record, blobs, [c["id"] for c in matched]))


def advisory_result(record: dict[str, Any], blobs: dict[str, bytes], components: list[str]) -> dict[str, Any]:
    subject = record["subject"]
    response = parse_json(blobs[record["sha256"]])
    require(isinstance(response, dict), "Invalid advisory response.")
    if record.get("format") == "osv-querybatch":
        require(urllib.parse.urlsplit(record["url"]).hostname == "api.osv.dev", "Unexpected OSV evidence host.")
        request = parse_json(blobs[record["requestSha256"]])
        require(isinstance(request, dict) and isinstance(request.get("queries"), list)
                and isinstance(response.get("results"), list)
                and len(request["queries"]) == len(response["results"]), "Incomplete OSV batch response.")
        index = record.get("queryIndex")
        require(type(index) is int and 0 <= index < len(request["queries"]), "Invalid advisory query index.")
        expected = {"version": subject["version"], "package": {
            "name": subject["name"], "ecosystem": subject.get("ecosystem", "PyPI"),
        }}
        require(request["queries"][index] == expected, "Advisory query subject mismatch.")
        cell = response["results"][index]
        require(isinstance(cell, dict) and set(cell) <= {"vulns", "next_page_token"}, "Unknown OSV result shape.")
        findings = cell.get("vulns", [])
        require(isinstance(cell.get("next_page_token", ""), str), "Invalid OSV pagination status.")
        incomplete = bool(cell.get("next_page_token"))
    elif record.get("format") == "pypi-version-json":
        require(urllib.parse.urlsplit(record["url"]).hostname == "pypi.org", "Unexpected PyPI evidence host.")
        require(subject.get("ecosystem", "PyPI") == "PyPI", "Invalid PyPI advisory ecosystem.")
        info = response.get("info")
        require(isinstance(info, dict) and normalized(info.get("name")) == subject["name"]
                and info.get("version") == subject["version"], "PyPI advisory subject mismatch.")
        require("vulnerabilities" in response, "PyPI advisory status is unavailable.")
        findings = response["vulnerabilities"]
        incomplete = False
    else:
        raise ValueError("Unsupported advisory evidence format.")
    require(isinstance(findings, list) and len(findings) <= 10_000, "Invalid advisory findings.")
    ids = []
    for finding in findings:
        require(isinstance(finding, dict) and isinstance(finding.get("id"), str)
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", finding["id"]), "Invalid advisory identifier.")
        ids.append(finding["id"])
    return {"evidence": record["id"], "components": sorted(components), "subject": subject,
            "retrievedAt": record["retrievedAt"], "responseSha256": record["sha256"],
            "status": ("pagination-incomplete" if incomplete else
                       "findings-require-review" if ids else "queried-no-matches"),
            "advisoryIds": sorted(set(ids)), "vulnerabilityFreeClaim": False}


def obligations(inventory: Inventory, records: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []

    def add(code: str, item: dict[str, Any], detail: str) -> None:
        findings.append({"code": code, "component": item["id"], "detail": detail})

    for item in inventory.components:
        kind = item["kind"]
        if kind == "native-file":
            add("native_build_provenance_unresolved", item,
                "File bytes are inventoried; exact native source/dependencies/toolchain/build binding is not established.")
            continue
        if kind in {"vendored-declaration", "cargo-declaration"}:
            add("declared_dependency_closure_unverified", item,
                "A declaration is not proof of exact compiled/vendored source, license coverage or advisory closure.")
            continue
        if not item["notices"]:
            add("license_text_missing", item, "No matching original license/notice text was identified.")
        if item["name"] in policy["firstPartyNames"]:
            continue  # First-party code review is a separate gate; do not query private package names.
        if item["name"] in policy["sourceObligations"]:
            add("corresponding_source_review_required", item,
                policy["sourceObligations"][item["name"]]["requiredReview"])
            for conflict in policy["sourceObligations"][item["name"]].get("declarationConflicts", []):
                if item["version"] == conflict["version"] and item.get("declaredLicense") == conflict["packageDeclaration"]:
                    add("source_license_declaration_conflict", item, conflict["requiredReview"])
        relevant = [r for r in records if r["subject"] == {
            "name": item["name"], "version": item["version"], "sha256": item["sha256"],
            **({"ecosystem": r["subject"]["ecosystem"]} if "ecosystem" in r["subject"] else {}),
        } and r["kind"] == "advisory"]
        if not relevant or any(r["status"] != "retrieved" for r in relevant):
            add("advisory_coverage_unknown", item, "No complete retrieved exact-version/hash-bound advisory record.")
        elif any(r.get("review") != "query-recorded-not-triaged" for r in relevant):
            add("advisory_record_requires_review", item, "Advisory evidence has not been classified.")
        else:
            add("advisory_triage_required", item,
                "Queries are recorded; results, ecosystem coverage and freshness require review, not automatic suppression.")
        if kind == "runtime":
            add("runtime_dependency_closure_unverified", item,
                "Runtime-native and vendored dependency/license/source closure is not established by the archive or lockfile alone.")
    for result in inventory.advisories:
        if result["advisoryIds"] or result["status"] == "pagination-incomplete":
            for ref in result["components"]:
                findings.append({"code": "advisory_findings_or_incomplete_results", "component": ref,
                                 "detail": "Recorded advisories/pagination require review: "
                                 + ", ".join(result["advisoryIds"]),
                                 "evidence": [result["evidence"]],
                                 "advisoryIds": result["advisoryIds"]})
    for record in records:
        if record["status"] != "retrieved":
            for item in inventory.components:
                if all(item[key] == record["subject"][key] for key in ("name", "version", "sha256")):
                    add("supplement_evidence_unresolved", item,
                        f"Evidence {record['id']} is {record['status']}; its recorded limitation requires review.")
    for record in inventory.vendor_manifests:
        if record["unresolvedDeclarations"]:
            findings.append({"code": "vendor_versions_unresolved", "component": record["location"],
                             "detail": "Vendor manifest contains declarations without a simple exact name/version pin."})
    return sorted(findings, key=lambda x: (x["component"], x["code"]))


def sbom(inventory: Inventory, manifest: dict[str, Any]) -> dict[str, Any]:
    components = []
    for item in sorted(inventory.components, key=lambda c: c["id"]):
        entry = {"bom-ref": item["id"], "type": "file" if item["kind"] == "native-file" else "library",
                 "name": item["name"],
                 "properties": [{"name": "polaris:kind", "value": item["kind"]},
                                {"name": "polaris:location", "value": item["location"]},
                                {"name": "polaris:hash-scope", "value": item["hashScope"]},
                                {"name": "polaris:evidence-sha256", "value": item["sha256"]}]}
        if item["hashScope"] == "supplied-file":
            entry["hashes"] = [{"alg": "SHA-256", "content": item["sha256"]}]
        if item["version"] is not None:
            entry["version"] = item["version"]
            if item["kind"] in {"wheel", "ensurepip-wheel", "installed-distribution", "vendored-distribution",
                                "vendored-declaration"}:
                entry["purl"] = f"pkg:pypi/{item['name']}@{urllib.parse.quote(item['version'], safe='')}"
            elif item["kind"] == "cargo-declaration":
                entry["purl"] = f"pkg:cargo/{item['name']}@{urllib.parse.quote(item['version'], safe='')}"
        if item.get("declaredLicense"):
            entry["licenses"] = [{"license": {"name": item["declaredLicense"]}}]
        components.append(entry)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": manifest["id"], "version": manifest["version"]}},
            "components": components,
            "dependencies": [{"ref": item["id"], "dependsOn": sorted(c["id"] for c in inventory.components
                                                                    if c["parent"] == item["id"])}
                             for item in sorted(inventory.components, key=lambda c: c["id"])]}


def assemble(*, bundle_dir: Path, supplements: Path | None = None) -> dict[str, bytes]:
    """Replayable, data-only collection; no filesystem outputs or trusted decisions."""
    bundle_dir = canonical(bundle_dir)
    if supplements is not None:
        supplements = canonical(supplements)
    policy_data = read_regular(POLICY, MAX_METADATA)
    policy = parse_json(policy_data)
    require(policy.get("format") == "polaris.compliance-policy/2", "Unsupported compliance policy.")
    tools = {name: read_regular(ROOT / name, MAX_METADATA) for name in TOOL_FILES}
    tool_manifest = json_bytes({"format": "polaris.compliance-tools/1",
                               "files": [pin(content, name) for name, content in sorted(tools.items())]})
    data, manifest = load_bundle(bundle_dir)
    inventory = collect_bundle(data, manifest)
    records, blobs, supplement_inputs = load_supplements(supplements)
    apply_supplements(inventory, records, blobs)
    pending = obligations(inventory, records, policy)
    inputs = [pin(content, name) for name, content in sorted(data.items())]
    result = {
        "format": "polaris.release-input-inventory/2",
        "release": {k: manifest[k] for k in ("id", "version", "platform")},
        "inputArtifacts": inputs, "policySha256": sha(policy_data),
        "toolManifestSha256": sha(tool_manifest),
        "supplementInputs": supplement_inputs,
        "counts": {"outerWheels": len(inventory.outer),
                   "outerNameVersionPairs": len({(c["name"], c["version"]) for c in inventory.outer}),
                   "componentsByKind": dict(sorted(collections.Counter(c["kind"] for c in inventory.components).items())),
                   "nativeFilesByFormat": dict(sorted(collections.Counter(c["binaryFormat"] for c in inventory.components
                                                                        if c["kind"] == "native-file").items()))},
        "components": sorted(inventory.components, key=lambda c: c["id"]),
        "files": sorted(inventory.files, key=lambda f: f["location"]),
        "vendorManifests": sorted(inventory.vendor_manifests, key=lambda f: f["location"]),
        "evidence": records,
        "advisoryResults": sorted(inventory.advisories, key=lambda r: r["evidence"]),
    }
    outputs: dict[str, bytes] = {"inventory.json": json_bytes(result), "sbom.cdx.json": json_bytes(sbom(inventory, manifest))}
    outputs["inputs/policy.json"] = policy_data
    outputs["inputs/tool-manifest.json"] = tool_manifest
    if supplements is not None:
        for name, digest in supplement_inputs.items():
            raw = read_regular(supplements / name)
            require(sha(raw) == digest, "Supplements changed during inventory.")
            outputs["inputs/supplements/" + name] = raw
    notices = [b"THIRD-PARTY MATERIALS: IDENTIFIED NOTICES, NOT LEGAL CLEARANCE\n"
               b"See compliance-report.json for missing evidence and unresolved obligations.\n"]
    for digest, content in sorted(inventory.notices.items()):
        locations = sorted({n["location"] for c in inventory.components for n in c["notices"] if n["sha256"] == digest})
        notices.extend([("\n--- SHA-256 " + digest + " ---\n" + "\n".join(locations) + "\n").encode(), content, b"\n"])
        outputs[f"licenses/{digest}.txt"] = content
    outputs["THIRD_PARTY_NOTICES.txt"] = b"".join(notices)
    for record in records:
        if record["status"] == "retrieved" and record["kind"] != "license":
            directory = "sources" if record["kind"] == "source" else "evidence"
            outputs[f"{directory}/{record['sha256']}.data"] = blobs[record["sha256"]]
            if record.get("requestFile"):
                outputs[f"evidence/{record['requestSha256']}.data"] = blobs[record["requestSha256"]]
    report = {"format": "polaris.release-compliance/2", "stage": "observations", "release": result["release"],
              "inventoryComplete": True, "complete": False, "original": pending, "resolved": [],
              "unresolved": pending, "technicalComplete": False, "legalAuthorized": False,
              "securityAuthorized": False, "readyForSigning": False, "localEvidenceOnly": True,
              "policySha256": sha(policy_data), "toolManifestSha256": sha(tool_manifest),
              "inventoryScope": "Supplied archive members and identified declarations; native/transitive build closure remains separately unresolved.",
              "advisoryResults": result["advisoryResults"],
              "limitations": policy["limitations"], "inputArtifacts": inputs,
              "inventorySha256": sha(outputs["inventory.json"]),
              "files": [pin(content, name) for name, content in sorted(outputs.items())]}
    outputs["compliance-report.json"] = json_bytes(report)
    # Finish all validation before creating a destination. No input archives are ever extracted.
    require({name: sha(read_regular(bundle_dir / name)) for name in data}
            == {name: sha(content) for name, content in data.items()}, "Bundle changed during inventory.")
    if supplements is not None:
        require(all(sha(read_regular(supplements / name)) == digest for name, digest in supplement_inputs.items()),
                "Supplements changed during inventory.")
    require(read_regular(POLICY, MAX_METADATA) == policy_data, "Policy changed during inventory.")
    require(all(read_regular(ROOT / name, MAX_METADATA) == content for name, content in tools.items()),
            "Compliance tooling changed during inventory.")
    return outputs


def write_outputs(output: Path, outputs: dict[str, bytes]) -> None:
    """Write an already validated private tree, without replacing any existing path."""
    output = canonical(output)
    require(not output.exists() and output.parent.is_dir(), "Output must be new with an existing parent.")
    spellings: dict[str, str] = {}
    for name in outputs:
        member_path(name)
        for part in (name, *(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")):
            require(spellings.setdefault(part.casefold(), part) == part, "Ambiguous output path.")
        require(all(str(parent) not in outputs for parent in PurePosixPath(name).parents),
                "Output file has a file ancestor.")
    output.mkdir(mode=0o700)
    for name, content in sorted(outputs.items(), key=lambda item: (item[0] == "compliance-report.json", item[0])):
        path = output / name
        parent = output
        for part in PurePosixPath(name).parts[:-1]:
            parent /= part
            parent.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())


def build(*, bundle_dir: Path, output: Path, supplements: Path | None = None) -> dict[str, Any]:
    bundle_dir, output = canonical(bundle_dir), canonical(output)
    require(not output.exists(), "Output must be new; existing evidence is never replaced.")
    require(not output.is_relative_to(bundle_dir) and not bundle_dir.is_relative_to(output),
            "Output must not overlap bundle inputs.")
    require(output.parent.is_dir(), "Output parent must already exist.")
    if supplements is not None:
        supplements = canonical(supplements)
        require(not output.is_relative_to(supplements) and not supplements.is_relative_to(output),
                "Output must not overlap supplements.")
    outputs = assemble(bundle_dir=bundle_dir, supplements=supplements)
    write_outputs(output, outputs)
    return parse_json(outputs["compliance-report.json"], maximum=64 * 1024 * 1024)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--supplements", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(bundle_dir=args.bundle_dir, supplements=args.supplements, output=args.output)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, zipfile.BadZipFile, tarfile.TarError, csv.Error):
        print("Compliance inputs rejected; no completion report was produced.")
        return 1
    print(json.dumps({"complete": result["complete"], "inventoryComplete": result["inventoryComplete"],
                      "unresolved": len(result["unresolved"]), "inventorySha256": result["inventorySha256"]},
                     sort_keys=True))
    return 0 if result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

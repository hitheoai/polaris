"""Built-in Dockerfile analyzer: instructions are parsed from text, never built or run.

Handles parser directives (`# escape=`), line continuations, comment lines inside them,
heredocs, multi-stage builds, `FROM <stage>` and ARG-parameterized images. Reports remote
scripts piped into a shell and remote `ADD` without `--checksum`, credentials in ENV/ARG/RUN and
build arguments that carry secrets into image history, a final image that runs as root, and
base images not pinned by digest. ARG-parameterized images and unknown users are skipped, never
guessed: the rules under-report rather than flag what the file doesn't show.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from polaris.jsonio import digest_json
from polaris.review import catalog, secrets
from polaris.review.analyzers import shellwords
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.analyzers.evidence import make_finding, mask_values, step
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    Confidence,
    CoverageStatus,
    Severity,
    SourceFile,
    WorkflowFinding,
)

ANALYZER_ID = "polaris-dockerfile"
VERSION = "polaris-dockerfile/0.1.0"
KIND = "dockerfile"
CHECKS = ("secret_exposure", "excessive_privileges", "unpinned_dependency", "unverified_download")
LIMITATIONS = [
    "Dockerfile text only: base images, build contexts, entrypoint scripts and build arguments passed at "
    "build time are not inspected.",
    "Images parameterized by ARG are not resolved (never flagged as unpinned); a final stage with no USER "
    "is reported unless its base image is known to run as non-root or the file installs a privilege-drop "
    "tool (gosu, su-exec, setpriv).",
    "RUN shell commands are tokenized for pipes and substitutions, never executed or fully parsed.",
]
MAX_BYTES = 1_000_000
MAX_LINES = 20_000
MAX_INSTRUCTIONS = 5_000
MAX_HITS = 500

_DIRECTIVE = re.compile(r"^\s*#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(\S.*?)\s*$")
_HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z0-9_.-]+)\2")
_DIGEST = re.compile(r"(?i)@sha(?:256:[0-9a-f]{64}|512:[0-9a-f]{128})$")
_URL = re.compile(r"(?i)^(?:https?|ftp)://\S+$")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|([A-Za-z_][A-Za-z0-9_]*))")
_SECRET_NAME = re.compile(r"(?i)(?:^|_)(?:password|passwd|passphrase|secret|token|api_?key|apikey|access_?key|"
                          r"private_?key|client_?secret|credentials?)(?:_|$)")
_NOT_SECRET_NAME = re.compile(r"(?i)(?:_url|_uri|_endpoint|_path|_file|_dir|_name|_user(?:name)?|_host|_port|_id|"
                              r"_type|_version|_enabled|_disabled|_length|_ttl|_expir\w*|_header|_prefix)$|public|"
                              r"publishable|(?:^|_)(?:gpg|pgp)(?:_|$)")
_NON_ROOT_IMAGE = re.compile(r"(?i)nonroot|non-root|rootless|unprivileged|^(?:docker\.io/)?bitnami/|^cgr\.dev/chainguard/")
# Operating-system and language-runtime images that run as root unless USER changes it.
# Application images (apache/airflow, grafana/grafana...) often set their own non-root user,
# so a stage built FROM an image outside this list is never assumed to run as root.
_ROOT_IMAGES = frozenset({
    "ubuntu", "debian", "alpine", "centos", "fedora", "rockylinux", "almalinux", "amazonlinux", "oraclelinux",
    "archlinux", "busybox", "photon", "opensuse/leap", "opensuse/tumbleweed", "python", "pypy", "node", "golang",
    "rust", "ruby", "php", "perl", "openjdk", "eclipse-temurin", "amazoncorretto", "ibm-semeru-runtimes",
    "sapmachine", "maven", "gradle", "buildpack-deps", "elixir", "erlang", "haskell", "swift", "julia", "r-base",
    "clojure", "dart", "bash", "docker", "nginx", "httpd", "tomcat",
    "mcr.microsoft.com/dotnet/aspnet", "mcr.microsoft.com/dotnet/runtime", "mcr.microsoft.com/dotnet/sdk",
    "mcr.microsoft.com/dotnet/runtime-deps", "registry.access.redhat.com/ubi8/ubi",
    "registry.access.redhat.com/ubi9/ubi", "registry.access.redhat.com/ubi8/ubi-minimal",
    "registry.access.redhat.com/ubi9/ubi-minimal", "registry.access.redhat.com/ubi9/ubi-micro",
})


def runs_as_root_by_default(image: str) -> bool:
    """Whether an image reference names a known root-by-default image (or a root distroless one)."""
    name = image.split("@", 1)[0]
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rsplit(":", 1)[0]
    name = name.lower()
    for prefix in ("docker.io/library/", "docker.io/", "library/", "public.ecr.aws/docker/library/",
                   "mirror.gcr.io/library/"):
        name = name.removeprefix(prefix)
    if name.startswith("gcr.io/distroless/"):
        return not _NON_ROOT_IMAGE.search(image)
    return name in _ROOT_IMAGES
# Images whose entrypoint drops privileges at runtime (the official database images do this).
_PRIVILEGE_DROP = re.compile(r"(?i)(?<![\w-])(?:gosu|su-exec|setpriv|runuser|s6-setuidgid|chpst|setuidgid)(?![\w-])")


@dataclass(frozen=True)
class Heredoc:
    delimiter: str
    body: str
    line: int  # first body line, 1-based


@dataclass
class Instruction:
    keyword: str
    text: str  # arguments, continuations joined and comment lines removed
    line: int
    end_line: int
    segments: list[tuple[int, int]]  # (offset in text, physical line)
    heredocs: list[Heredoc] = field(default_factory=list)

    def line_at(self, offset: int) -> int:
        line = self.line
        for start, physical in self.segments:
            if start > offset:
                break
            line = physical
        return line


class _Problem(Exception):
    """A fixed coverage reason; never carries input text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _heredoc_markers(text: str) -> list[tuple[str, bool]]:
    """`<<EOF` / `<<-"EOF"` markers outside quotes, as (delimiter, strip_tabs)."""
    found = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"':
                index += 1
        elif char in "'\"":
            quote = char
        elif text.startswith("<<", index) and not text.startswith("<<<", index):
            match = _HEREDOC.match(text, index)
            if match:
                found.append((match.group(3), bool(match.group(1))))
                index = match.end()
                continue
        index += 1
    return found


def parse(text: str) -> list[Instruction]:
    """Instructions in order. Unterminated heredocs and invalid directives raise
    `_Problem("parse_error")`; size budgets raise `_Problem("analysis_limit")`."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    if len(lines) > MAX_LINES:
        raise _Problem("analysis_limit")
    escape = "\\"
    index = 0
    while index < len(lines):
        match = _DIRECTIVE.match(lines[index])
        if match is None or match.group(1).lower() not in ("syntax", "escape", "check"):
            break
        if match.group(1).lower() == "escape":
            if match.group(2) not in ("\\", "`"):
                raise _Problem("parse_error")
            escape = match.group(2)
        index += 1
    continuation = re.compile(re.escape(escape) + r"[ \t]*$")
    instructions: list[Instruction] = []
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        first = index + 1
        logical = ""
        segments: list[tuple[int, int]] = []
        while True:
            current = lines[index]
            match = continuation.search(current)
            segments.append((len(logical), index + 1))
            logical += current[:match.start()] if match else current
            index += 1
            if not match:
                break
            while index < len(lines) and (not lines[index].strip() or lines[index].lstrip().startswith("#")):
                index += 1
            if index >= len(lines):
                break
        leading = len(logical) - len(logical.lstrip())
        body = logical[leading:]
        keyword, _, rest = body.partition(" ") if " " in body.split("\t", 1)[0] or "\t" not in body \
            else body.partition("\t")
        offset = leading + len(keyword) + 1
        arguments = rest.lstrip()
        offset += len(rest) - len(arguments)
        shifted = [(max(0, start - offset), line) for start, line in segments]
        instruction = Instruction(keyword.upper(), arguments, first, index, shifted)
        if instruction.keyword in ("RUN", "COPY", "ADD", "ONBUILD"):
            for delimiter, strip_tabs in _heredoc_markers(arguments):
                start = index
                while index < len(lines) and (lines[index].lstrip("\t") if strip_tabs else lines[index]) != delimiter:
                    index += 1
                if index >= len(lines):
                    raise _Problem("parse_error")
                instruction.heredocs.append(Heredoc(delimiter, "\n".join(lines[start:index]), start + 1))
                index += 1
            instruction.end_line = max(instruction.end_line, index)
        instructions.append(instruction)
        if len(instructions) > MAX_INSTRUCTIONS:
            raise _Problem("analysis_limit")
    return instructions


def _flags(text: str) -> tuple[dict[str, str], str, int]:
    """Leading `--name[=value]` flags of an instruction, the remaining text and its offset."""
    flags: dict[str, str] = {}
    offset = 0
    while text.startswith("--", offset):
        end = offset
        quote = ""
        while end < len(text) and (quote or not text[end].isspace()):
            if text[end] in "'\"":
                quote = "" if quote == text[end] else quote or text[end]
            end += 1
        name, _, value = text[offset + 2:end].partition("=")
        flags[name.lower()] = value
        offset = end
        while offset < len(text) and text[offset].isspace():
            offset += 1
    return flags, text[offset:], offset


def _words(text: str) -> list[tuple[str, int]]:
    """Whitespace-separated words with quotes removed, and their offsets."""
    words = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        start = index
        current = []
        quote = ""
        while index < len(text) and (quote or not text[index].isspace()):
            char = text[index]
            if quote:
                if char == quote:
                    quote = ""
                elif char == "\\" and quote == '"' and index + 1 < len(text):
                    index += 1
                    current.append(text[index])
                else:
                    current.append(char)
            elif char in "'\"":
                quote = char
            elif char == "\\" and index + 1 < len(text):
                index += 1
                current.append(text[index])
            else:
                current.append(char)
            index += 1
        words.append(("".join(current), start))
    return words


def _pairs(instruction: Instruction) -> list[tuple[str, str | None, int]]:
    """(name, value, offset) of ENV/ARG declarations; legacy `ENV NAME value` included."""
    text = instruction.text
    words = _words(text)
    if not words:
        return []
    if instruction.keyword == "ENV" and "=" not in words[0][0]:
        name, offset = words[0]
        value = text[offset + len(name):].strip()
        return [(name, value, offset)]
    found: list[tuple[str, str | None, int]] = []
    for word, offset in words:
        name, separator, value = word.partition("=")
        if name:
            found.append((name, value if separator else None, offset))
    return found


@dataclass
class Stage:
    index: int
    name: str | None
    image: str
    line: int
    base: Stage | None
    user: tuple[str, int] | None = None
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"stage {self.name or self.index}"

    def chain(self) -> list[Stage]:
        stages: list[Stage] = []
        current: Stage | None = self
        while current is not None and current not in stages:
            stages.append(current)
            current = current.base
        return stages


@dataclass
class Hit:
    check: str
    rule: str
    line: int
    message: str
    severity: Severity
    symbol: str = "<module>"
    trace: list[tuple[str, int, str]] = field(default_factory=list)
    confidence: Confidence = "high"
    secret: str | None = None  # the literal to mask in every finding's snippet


def _rules() -> None:
    docker = "polaris.docker."
    catalog.rule(docker + "unverified_download.pipe_to_shell", "unverified_download", "Remote script piped to a shell",
                 "A RUN instruction downloads a script and executes it without verifying it.",
                 "Download to a file, check a pinned SHA-256 (sha256sum -c) or signature, then run it; or install "
                 "from a package repository whose signing key you pin.")
    catalog.rule(docker + "unverified_download.remote_add", "unverified_download", "Remote ADD without a checksum",
                 "ADD downloads a remote file into the image without verifying it.",
                 "Add --checksum=sha256:<digest> to the ADD instruction (Dockerfile syntax 1.6+), or download "
                 "and verify it in a RUN step.")
    catalog.rule(docker + "secret_exposure.hardcoded", "secret_exposure", "Credential hardcoded in a Dockerfile",
                 "A credential appears to be written directly in the Dockerfile, so it ships in the image "
                 "layers and history.",
                 "Remove it, rotate it, and pass secrets at build time with RUN --mount=type=secret.")
    catalog.rule(docker + "secret_exposure.build_arg", "secret_exposure", "Secret passed as a build argument",
                 "A secret-named build argument is recorded in the image history of the commands that use it.",
                 "Use a BuildKit secret mount (RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN …) instead of ARG.")
    catalog.rule(docker + "secret_exposure.env_from_arg", "secret_exposure", "Build secret copied into ENV",
                 "ENV copies a secret-named value into the image configuration, readable by anyone who can pull "
                 "the image.",
                 "Don't persist secrets in ENV; use a secret mount for build steps and inject runtime secrets when "
                 "the container starts.")
    catalog.rule(docker + "excessive_privileges.root_user", "excessive_privileges", "Final image runs as root",
                 "The final stage switches to root and doesn't switch back.",
                 "End the final stage with USER <non-root user> (create it first with useradd/adduser), after the "
                 "steps that need root.")
    catalog.rule(docker + "excessive_privileges.no_user", "excessive_privileges", "Final image has no non-root USER",
                 "The final stage never sets USER, so the container runs as root unless its base image changes it.",
                 "Create an unprivileged user and add USER <name> at the end of the final stage.")
    catalog.rule(docker + "unpinned_dependency.image", "unpinned_dependency", "Image not pinned to a digest",
                 "An image is referenced by a mutable tag.",
                 "Pin the image by digest (FROM name:tag@sha256:<digest>) and update it deliberately (Dependabot "
                 "and Renovate can).")


_rules()


def capability() -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available", version=VERSION, expected_version=VERSION,
        rule_pack_version=VERSION,
        rule_pack_digest=digest_json({"version": VERSION,
                                      "rules": sorted(rule for rule in catalog.RULES if rule.startswith("polaris.docker."))}),
        languages=[KIND], checks=list(CHECKS), provenance="Original Polaris rules (Dockerfile text parser)",
        license="Apache-2.0", reason="builtin_in_process", limitations=list(LIMITATIONS),
    )


def _quote(text: str, limit: int = 90) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed if len(collapsed) <= limit else collapsed[:limit - 1] + "…"


def _image_kind(image: str, stages: dict[str, Stage]) -> str:
    lowered = image.lower()
    if "$" in image or any(mark in image for mark in ("{{", "}}", "%", "<", ">")):
        return "parameterized"
    if lowered in stages:
        return "stage"
    if lowered == "scratch":
        return "scratch"
    return "pinned" if _DIGEST.search(image) else "tag"


def _body_lines(heredoc: Heredoc) -> Callable[[int], int]:
    """Physical line of an offset in a heredoc body."""
    def line_at(position: int) -> int:
        return heredoc.line + heredoc.body.count("\n", 0, position)
    return line_at


def _from_parts(instruction: Instruction) -> tuple[str, str | None, int]:
    """(image, lower-cased stage name, offset of the image) of a FROM instruction."""
    _, rest, offset = _flags(instruction.text)
    words = _words(rest)
    image = words[0][0] if words else ""
    name = words[2][0].lower() if len(words) >= 3 and words[1][0].lower() == "as" else None
    return image, name, offset + (words[0][1] if words else 0)


def shipped_stages(instructions: list[Instruction]) -> set[int]:
    """Indexes of the stages whose layers end up in the final image (the last stage and the
    stages it is built FROM, transitively)."""
    bases: list[int | None] = []
    named: dict[str, int] = {}
    for instruction in instructions:
        if instruction.keyword == "FROM":
            image, name, _ = _from_parts(instruction)
            bases.append(named.get(image.lower()))
            if name:
                named[name] = len(bases) - 1
    shipped: set[int] = set()
    current: int | None = len(bases) - 1 if bases else None
    while current is not None and current not in shipped:
        shipped.add(current)
        current = bases[current]
    return shipped


class _Analysis:
    def __init__(self, source: SourceFile, instructions: list[Instruction], checks: set[str]) -> None:
        self.source = source
        self.path = source.path
        self.instructions = instructions
        self.checks = checks
        self.hits: list[Hit] = []
        self.secrets: set[str] = set()  # masked in every finding, whichever checks run
        self.stages: list[Stage] = []
        self.named: dict[str, Stage] = {}
        self.shipped = shipped_stages(instructions)

    def add(self, hit: Hit) -> None:
        if hit.secret:
            self.secrets.add(hit.secret)
        if hit.check in self.checks and len(self.hits) < MAX_HITS:
            self.hits.append(hit)

    def run(self) -> None:
        stage: Stage | None = None
        for instruction in self.instructions:
            keyword = instruction.keyword
            if keyword == "FROM":
                stage = self.from_(instruction)
                continue
            if stage is None:
                continue  # global ARGs (only usable in FROM) and parser noise
            stage.instructions.append(instruction)
            if keyword == "USER":
                value = _words(instruction.text)
                if value:
                    stage.user = (value[0][0], instruction.line)
            elif keyword in ("RUN", "ONBUILD"):
                self.run_(instruction, stage)
            elif keyword in ("ADD", "COPY"):
                self.copy(instruction, stage)
            elif keyword in ("ENV", "ARG"):
                self.declaration(instruction, stage)
        self.hardcoded()
        if self.stages:
            self.user(self.stages[-1])

    def from_(self, instruction: Instruction) -> Stage:
        image, name, offset = _from_parts(instruction)
        kind = _image_kind(image, self.named)
        stage = Stage(len(self.stages), name, image, instruction.line,
                      self.named.get(image.lower()) if kind == "stage" else None)
        self.stages.append(stage)
        if name:
            self.named[name] = stage
        if kind == "tag":
            tagged = ":" in image.rsplit("/", 1)[-1]
            line = instruction.line_at(offset)
            self.add(Hit("unpinned_dependency", "polaris.docker.unpinned_dependency.image", line,
                         f"{_quote(image, 80)} is a mutable {'tag' if tagged else 'reference (implicitly :latest)'}: "
                         "whoever controls it can change what this image is built from.", "low", stage.label))
        return stage

    def copy(self, instruction: Instruction, stage: Stage) -> None:
        flags, rest, offset = _flags(instruction.text)
        source = flags.get("from")
        if instruction.keyword == "COPY" and source and not source.isdigit():
            if _image_kind(source, self.named) == "tag":
                self.add(Hit("unpinned_dependency", "polaris.docker.unpinned_dependency.image", instruction.line,
                             f"COPY --from={_quote(source, 80)} copies files from a mutable image tag.", "low",
                             stage.label))
        if instruction.keyword != "ADD" or "checksum" in flags:
            return
        if rest.lstrip().startswith("["):
            try:
                parsed = json.loads(rest)
            except ValueError:
                parsed = None
            words = [(item, 0) for item in parsed] if isinstance(parsed, list) and all(
                isinstance(item, str) for item in parsed) else []
        else:
            words = _words(rest)
        for word, position in words[:-1]:
            if not _URL.match(word) or re.search(r"(?i)\.git(?:#|$)|#", word):
                continue
            insecure = not word.lower().startswith("https://")
            line = instruction.line_at(offset + position)
            self.add(Hit("unverified_download", "polaris.docker.unverified_download.remote_add", line,
                         f"ADD downloads {_quote(word, 80)} without --checksum"
                         + (" over an unencrypted connection, so anyone on the network path can replace it."
                            if insecure else ", so a changed or compromised file goes into the image unnoticed."),
                         "medium" if insecure else "low", stage.label,
                         [("source", line, _quote(word, 80)), ("sink", line, "ADD")]))

    def run_(self, instruction: Instruction, stage: Stage) -> None:
        text = instruction.text
        base = 0
        if instruction.keyword == "ONBUILD":
            inner, _, rest = text.partition(" ")
            if inner.upper() == "ADD":
                self.copy(Instruction("ADD", rest.lstrip(), instruction.line, instruction.end_line,
                                      [(0, instruction.line)]), stage)
                return
            if inner.upper() != "RUN":
                return
            base = len(text) - len(rest.lstrip())
            text = rest.lstrip()
        flags, command, offset = _flags(text)
        offset += base
        scripts: list[tuple[str, Callable[[int], int]]] = []
        if command.lstrip().startswith("["):
            try:
                parsed = json.loads(command)
            except ValueError:
                parsed = None
            if (isinstance(parsed, list) and len(parsed) >= 3 and all(isinstance(item, str) for item in parsed)
                    and shellwords.basename(parsed[0]) in shellwords.SHELLS and parsed[1] == "-c"):
                scripts.append((parsed[2], lambda _: instruction.line))
        else:
            scripts.append((command, lambda position: instruction.line_at(offset + position)))
            heading = _HEREDOC.sub("", command).strip()
            runs_body = not heading or (shellwords.basename(heading.split()[0]) in shellwords.SHELLS
                                        and "-c" not in heading.split())
            if runs_body:
                scripts.extend((heredoc.body, _body_lines(heredoc)) for heredoc in instruction.heredocs)
        for script, line_at in scripts:
            for found in shellwords.remote_scripts(script):
                if not shellwords.is_remote(found.url):
                    continue
                insecure = bool(found.url and re.match(r"(?i)(?:http|ftp)://", found.url))
                line = line_at(found.start)
                target = _quote(found.url, 80) if found.url else "a remote script"
                self.add(Hit("unverified_download", "polaris.docker.unverified_download.pipe_to_shell", line,
                             f"{target} is downloaded and piped into {found.interpreter} without verification"
                             + (" over an unencrypted connection, so anyone on the network path can replace it."
                                if insecure else "; whoever controls that server or URL controls what goes into "
                                                 "this image."),
                             "high" if insecure else "low", stage.label,
                             [("source", line, target), ("sink", line, found.interpreter)]))

    def declaration(self, instruction: Instruction, stage: Stage) -> None:
        ships = stage.index in self.shipped
        for name, value, offset in _pairs(instruction):
            if not _SECRET_NAME.search(name) or _NOT_SECRET_NAME.search(name):
                continue
            line = instruction.line_at(offset)
            literal = value if value is not None and not _VARIABLE.search(value) else None
            if literal is not None and self.random_literal(literal):
                self.add(Hit("secret_exposure", "polaris.docker.secret_exposure.hardcoded", line,
                             f"{instruction.keyword} {_quote(name, 60)} holds a long random literal "
                             f"({secrets.mask(literal)}) that ships in the image.", "medium", stage.label,
                             confidence="medium", secret=literal))
                continue
            if instruction.keyword == "ENV" and value is not None and _VARIABLE.search(value):
                self.add(Hit("secret_exposure", "polaris.docker.secret_exposure.env_from_arg", line,
                             f"ENV {_quote(name, 60)} copies a build value into the image configuration"
                             + (", where anyone who can pull the final image can read it." if ships else
                                " of a build stage (not the final image, but its cache and history keep it)."),
                             "high" if ships else "low", stage.label))
            elif instruction.keyword == "ARG" and literal is None:
                self.add(Hit("secret_exposure", "polaris.docker.secret_exposure.build_arg", line,
                             f"Build argument {_quote(name, 60)} looks like a secret; its value is recorded in the "
                             "history of the RUN steps that use it"
                             + (" and ships with the final image." if ships else " of this build stage."),
                             "medium" if ships else "low", stage.label))

    @staticmethod
    def random_literal(value: str) -> bool:
        return (16 <= len(value) <= 200 and not re.search(r"\s", value) and secrets.entropy(value) >= 3.5
                and bool(re.search(r"[0-9]", value)) and bool(re.search(r"[A-Za-z]", value))
                and not secrets.PLACEHOLDER.search(value) and not any(p.regex.search(value) for p in secrets.PATTERNS))

    def hardcoded(self) -> None:
        lines = (self.source.after or "").splitlines()
        reported: set[int] = set()
        for number, line in enumerate(lines, 1):
            if len(line) > 4_000:
                continue
            for pattern in secrets.PATTERNS:
                if pattern.literals and not any(item in line for item in pattern.literals):
                    continue
                match = next((item for item in pattern.regex.finditer(line)
                              if not secrets.PLACEHOLDER.search(item.group(0))), None)
                if match is None or number in reported:
                    continue
                reported.add(number)
                self.add(Hit("secret_exposure", "polaris.docker.secret_exposure.hardcoded", number,
                             f"A credential appears to be hardcoded in the Dockerfile ({pattern.label}, "
                             f"{secrets.mask(match.group(0))}); it ships in the image layers and history.",
                             pattern.severity, secret=match.group(0)))

    def user(self, final: Stage) -> None:
        if self.path.startswith(".devcontainer/") or "/.devcontainer/" in self.path:
            return
        chain = final.chain()
        if any(_PRIVILEGE_DROP.search(instruction.text) for stage in chain for instruction in stage.instructions):
            return
        current = next((stage.user for stage in chain if stage.user is not None), None)
        if current is not None:
            value, line = current
            account = value.split(":", 1)[0]
            if account in ("root", "0"):
                self.add(Hit("excessive_privileges", "polaris.docker.excessive_privileges.root_user", line,
                             f"USER {_quote(value, 40)} is the last user of the final stage, so the container runs as root.",
                             "low", final.label))
            return
        origin = chain[-1]
        kind = _image_kind(origin.image, {})
        if kind != "scratch" and (kind not in ("tag", "pinned") or not runs_as_root_by_default(origin.image)):
            return
        runnable = any(instruction.keyword in ("CMD", "ENTRYPOINT") for stage in chain for instruction in stage.instructions)
        if kind == "scratch" and not runnable:
            return  # an export-only stage (docker build --output), not a container that runs
        self.add(Hit("excessive_privileges", "polaris.docker.excessive_privileges.no_user", final.line,
                     f"The final stage ({_quote(final.image, 60)}) never sets USER, and "
                     + ("scratch has no other user" if kind == "scratch"
                        else f"{_quote(origin.image.split('@', 1)[0], 60)} runs as root by default")
                     + ", so the container runs as root.", "low", final.label))


def analyze_dockerfile(source: SourceFile, checks: set[str]) -> tuple[list[Hit], set[str]]:
    """Hits for one Dockerfile and the credential values it contains (to mask); raises
    `_Problem` with a fixed reason when the file can't be analyzed."""
    text = source.after or ""
    if len(text) > MAX_BYTES or len(text.encode("utf-8")) > MAX_BYTES:
        raise _Problem("file_too_large")
    analysis = _Analysis(source, parse(text), checks)
    try:
        analysis.run()
    except shellwords.ShellLimit:
        raise _Problem("analysis_limit") from None
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    analysis.hits.sort(key=lambda hit: (rank[hit.severity], hit.line, hit.rule))
    unique: dict[tuple[int, str], Hit] = {}
    for hit in analysis.hits:
        unique.setdefault((hit.line, hit.rule), hit)
    return list(unique.values()), analysis.secrets


class DockerfileAnalyzer:
    analyzer_id = ANALYZER_ID

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        checks = [check for check in request.checks if check in CHECKS]
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        if not checks:
            return AnalyzerResult(capability=capability())
        for source in request.sources:
            if source.role != "review" or source.skip or source.after is None or language_for_path(source.path) != KIND:
                continue
            status: CoverageStatus = "checked"
            reason = "builtin_rules_completed"
            detected: set[str] = set()
            try:
                hits, detected = analyze_dockerfile(source, set(checks))
            except _Problem as problem:
                status, reason, hits = "not_checked", problem.reason, []
            except (RecursionError, MemoryError):
                status, reason, hits = "not_checked", "analysis_error", []
            for hit in hits:
                findings.append(mask_values(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                    rule_id=hit.rule, result="flagged", start_line=hit.line, symbol=hit.symbol, message=hit.message,
                    severity=hit.severity, confidence=hit.confidence,
                    trace=[step(kind, line, label) for kind, line, label in hit.trace],
                    evidence=request.config.evidence,
                ), detected))
            coverage.extend(CheckCoverage(path=source.path, language=KIND, check_id=check, analyzer_id=ANALYZER_ID,
                                          status=status, reason=reason) for check in checks)
        return AnalyzerResult(findings=tuple(findings), coverage=tuple(coverage), capability=capability())

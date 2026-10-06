"""Your AI settings: one file you own, `~/.polaris/ai.toml`. Nothing here sends anything.

    endpoint = "https://api.example.com/v1/chat/completions"
    model = "your-model-name"
    allow_hosted = true            # you accept sending code to a service that isn't on this computer
    key_env = "YOUR_KEY_VARIABLE"  # the NAME of an environment variable that holds the key

The key itself is never in the file, never printed and never written anywhere. The file is read
only when you ask for `--ai`. It is refused when it is a symbolic link, is not yours, can be read
by other users, sits inside the project, or has settings Polaris doesn't know. A repository can
never turn AI on or change where code is sent: no project file is read for any of this.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from polaris.engineering.actions import scope_url
from polaris.engineering.errors import EngineeringError
from polaris.engineering.generation_models import GenerationConfig
from polaris.integrations._safe import IntegrationProblem, no_symlinks, read_snapshot
from polaris.review.loader import polaris_home

FILE_NAME = "ai.toml"
MAX_BYTES = 8192
KEYS = frozenset({"endpoint", "model", "allow_hosted", "key_env"})
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
# Variables CI systems set. `--ai` is for your own computer: a job may hold credentials that other
# people's changes can reach, and source code must not be sent from there.
CI_VARIABLES = ("GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TF_BUILD",
                "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID")


class AiProblem(Exception):
    """A fixed code (plus, for a missing key, the variable's name). Never a value from the file."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code, self.detail = code, detail
        super().__init__(code)


@dataclass(frozen=True)
class AiSettings:
    endpoint: str
    model: str
    allow_hosted: bool
    key_env: str | None
    path: Path

    @property
    def host(self) -> str:
        return scope_url(self.endpoint)[1]

    @property
    def local(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False


def settings_path() -> Path:
    return polaris_home() / FILE_NAME


def in_ci(environ: Mapping[str, str] | None = None) -> bool:
    values = os.environ if environ is None else environ
    if values.get("CI", "").strip().lower() not in ("", "0", "false", "no"):
        return True
    return any(values.get(name, "").strip() for name in CI_VARIABLES)


def _private(path: Path) -> None:
    """Refuse the file unless it and its folder belong to you alone."""
    info = path.stat()
    folder = path.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or folder.st_uid != os.getuid() or folder.st_mode & 0o022):
        raise AiProblem("unsafe_file")


def load_settings(path: Path | None = None, *, project: Path | None = None) -> AiSettings:
    target = path if path is not None else settings_path()
    try:
        target = no_symlinks(target)
        if project is not None and target.is_relative_to(Path(os.path.abspath(project))):
            raise AiProblem("inside_project")
        snapshot = read_snapshot(target, limit=MAX_BYTES)
        if snapshot is None:
            raise AiProblem("not_configured")
        _private(target)
    except (IntegrationProblem, OSError):
        raise AiProblem("unsafe_file") from None
    try:
        data = tomllib.loads(snapshot.value.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeError, RecursionError):
        raise AiProblem("invalid_file") from None
    endpoint, model = data.get("endpoint"), data.get("model")
    allow, key_env = data.get("allow_hosted", False), data.get("key_env")
    if (not set(data) <= KEYS or not isinstance(endpoint, str) or not isinstance(model, str)
            or not isinstance(allow, bool)
            or not (key_env is None or isinstance(key_env, str) and ENV_NAME.fullmatch(key_env))):
        raise AiProblem("invalid_file")
    try:
        # The same validation the gateway applies: HTTPS (or literal loopback), no secrets in the text.
        GenerationConfig(enabled=True, endpoint=endpoint, model=model, allow_hosted=allow)
        settings = AiSettings(endpoint, model, allow, key_env, target)
        settings.host  # noqa: B018 - parse once so a malformed endpoint fails here
    except (ValueError, EngineeringError):
        raise AiProblem("invalid_file") from None
    if not settings.local and not settings.allow_hosted:
        raise AiProblem("hosted_not_allowed", settings.host)
    return settings


def generation_config(settings: AiSettings, environ: Mapping[str, str] | None = None) -> GenerationConfig:
    """The gateway configuration, with the key read from the named environment variable."""
    values = os.environ if environ is None else environ
    key = None
    if settings.key_env is not None:
        value = values.get(settings.key_env, "").strip()
        if not value:
            raise AiProblem("missing_key", settings.key_env)
        key = SecretStr(value)
    try:
        return GenerationConfig(enabled=True, endpoint=settings.endpoint, model=settings.model,
                                allow_hosted=settings.allow_hosted, api_key=key)
    except (ValueError, EngineeringError):
        # Never echo the validation error: it can quote the key.
        raise AiProblem("invalid_key", settings.key_env or "") from None

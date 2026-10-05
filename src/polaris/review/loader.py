"""Find and load a local Polaris model bundle. Nothing here downloads anything."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def polaris_home() -> Path:
    return Path(os.environ.get("POLARIS_HOME", "~/.polaris")).expanduser()


def resolve_model(model: str | Path | None = None) -> Path | None:
    """Explicit path, then $POLARIS_MODEL, then ~/.polaris/models/current (a folder or pointer file)."""
    for candidate in (model, os.environ.get("POLARIS_MODEL")):
        if candidate:
            path = Path(candidate).expanduser()
            return path if path.is_dir() else None
    current = polaris_home() / "models" / "current"
    if current.is_dir() and not current.is_symlink():
        return current
    if current.is_file():
        target = Path(current.read_text(encoding="utf-8").strip()).expanduser()
        if not target.is_absolute():
            target = current.parent / target
        return target if target.is_dir() else None
    return None


def auto_device() -> str:
    try:
        import torch
    except ImportError:
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available() and os.environ.get("PYTORCH_ENABLE_MPS_FALLBACK", "0") == "0":
        return "mps"
    return "cpu"


def load_backend(model: str | Path | None = None, *, device: str = "auto",
                 allow_experimental: bool = True) -> Any:
    """Load a verified bundle. Raises PolarisRuntimeError('model_unavailable') if none is found."""
    from polaris.errors import PolarisRuntimeError

    path = resolve_model(model)
    if path is None:
        raise PolarisRuntimeError("model_unavailable")
    from polaris.runtime import LocalBackend

    chosen = auto_device() if device == "auto" else device
    return LocalBackend(path, device=chosen, allow_experimental=allow_experimental)

"""`polaris model ...`: install, update, check and switch local models."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_model_parsers(commands: Any) -> None:
    model = commands.add_parser("model", help="Install, check and switch local Polaris models.")
    actions = model.add_subparsers(dest="model_command", required=True)
    install = actions.add_parser("install", help="Install a model archive (.tar.gz) from disk.")
    install.add_argument("archive", type=Path)
    install.add_argument("--sha256", help="Expected checksum (default: the .sha256 file next to the archive).")
    install.add_argument("--no-activate", action="store_true", help="Install without making it the active model.")
    pull = actions.add_parser("pull", help="Download and install a model archive from an https:// URL.")
    pull.add_argument("url")
    pull.add_argument("--sha256", help="Expected checksum (default: the URL's .sha256 file).")
    pull.add_argument("--no-activate", action="store_true")
    actions.add_parser("list", help="List installed models.")
    use = actions.add_parser("use", help="Make an installed model the active one.")
    use.add_argument("name", help="Model folder name from `polaris model list`, or a path.")
    info = actions.add_parser("info", help="Show the active (or given) model.")
    info.add_argument("--model", type=Path)
    selftest = actions.add_parser("selftest", help="Check that the model runs correctly on this machine.")
    selftest.add_argument("--model", type=Path)
    selftest.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    remove = actions.add_parser("remove", help="Delete an installed model (not the active one).")
    remove.add_argument("name")
    pack = actions.add_parser("pack", help="Maintainers: package a model folder into a checksummed archive.")
    pack.add_argument("bundle", type=Path)
    pack.add_argument("--output", type=Path, required=True)
    for parser in (install, pull, info, selftest, pack, actions.choices["list"]):
        parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")


def _resolve_name(name: str) -> Path:
    from polaris.install import models_dir

    candidate = Path(name).expanduser()
    if candidate.is_dir():
        return candidate
    candidate = models_dir() / name
    if candidate.is_dir():
        return candidate
    matches = [path for path in models_dir().glob(f"{name}*") if path.is_dir()] if models_dir().is_dir() else []
    if len(matches) == 1:
        return matches[0]
    raise FileNotFoundError(f"no installed model called {name!r}; see `polaris model list`")


def _say(args: argparse.Namespace, payload: Any, text: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(text)


def _check_text(report: dict[str, Any]) -> str:
    if not report.get("loads"):
        return (f"  This machine can't use it safely ({report.get('error')}). Its self-test did not match; "
                "report this with your OS, chip and Python version.")
    test = report.get("self_test")
    if report.get("runtime_verified_by_self_test") and test:
        cached = " (cached)" if test.get("cached") else ""
        return (f"  Self-test passed on {report['device']}{cached}: {test['cases']} reference cases, "
                f"largest difference {test['max_delta']}, no decision changes.")
    return f"  Ready on {report['device']} (same setup the model was calibrated on)."


def run(args: argparse.Namespace) -> int:
    from polaris.errors import PolarisError
    from polaris.install import (
        InstallError,
        check_model,
        describe,
        install_archive,
        list_models,
        pack,
        pull,
        remove,
        use,
    )

    try:
        command = args.model_command
        if command in ("install", "pull"):
            if command == "install":
                result = install_archive(args.archive, sha256=args.sha256, activate=not args.no_activate)
            else:
                result = pull(args.url, sha256=args.sha256, activate=not args.no_activate)
            status = "installed and active" if result["active"] else "installed"
            _say(args, result, f"{result['model_version']} {status}.\n  Folder: {result['installed']}\n"
                                f"{_check_text(result)}")
            return 0 if result["loads"] else 3
        if command == "list":
            models = list_models()
            lines = [f"{'*' if m['active'] else ' '} {m['name']}  ({m.get('release_status', m.get('status'))})" for m in models]
            _say(args, models, "\n".join(lines) if lines else "No models installed. Run `polaris model install <archive>`.")
            return 0
        if command == "use":
            target = use(_resolve_name(args.name))
            print(f"Active model: {target.name}")
            return 0
        if command == "info":
            info = describe(args.model)
            if not info["installed"]:
                _say(args, info, "No model installed yet. Run `polaris model install <archive>` or `polaris model pull <url>`.")
                return 3
            _say(args, info, f"{info['model_version']} ({info['release_status']})\n  Folder: {info['path']}\n"
                             f"  Checks: {', '.join(info['supported_checks'])}\n  Calibrated on: {info['calibrated_runtime']}\n"
                             f"  Portable self-test included: {'yes' if info['self_test'] else 'no'}")
            return 0
        if command == "selftest":
            from polaris.review.loader import resolve_model

            selected = args.model or resolve_model()
            if selected is None:
                print("No model installed yet.", file=sys.stderr)
                return 3
            report = check_model(Path(selected), device=args.device)
            _say(args, report, f"{report['model_version']}\n{_check_text(report)}")
            return 0 if report["loads"] else 3
        if command == "remove":
            target = _resolve_name(args.name)
            remove(target)
            print(f"Removed {target.name}")
            return 0
        if command == "pack":
            result = pack(args.bundle, args.output)
            _say(args, result, f"Wrote {result['archive']} ({result['bytes'] / 1e6:.1f} MB)\n  sha256 {result['sha256']}")
            return 0
    except (InstallError, FileNotFoundError, OSError, ValueError, PolarisError) as exc:
        print(f"Polaris model: {exc}", file=sys.stderr)
        return 2
    return 2

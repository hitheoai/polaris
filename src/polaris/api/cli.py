"""`polaris serve`: the REST API, plus helpers to manage API keys and read usage."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from polaris.api.app import ApiSettings
    from polaris.api.security import KeyStore
    from polaris.integrations import ReviewService

DEFAULT_PORT = 8780
NEEDS_EXTRA = "The API server needs the optional 'api' dependencies: pip install 'theovex-polaris[api]'"


def add_serve_parsers(commands: Any) -> None:
    serve = commands.add_parser(
        "serve", help="Run the Polaris REST API (this machine only unless you add API keys).",
        description="Serve POST /v1/review and POST /v1/assess. Listens on 127.0.0.1 by default; "
                    "serving other machines requires API keys. Source is not persistently stored or logged; "
                    "optional workflow analysis can explicitly enable private temporary source files.",
    )
    serve.add_argument("--host", default="127.0.0.1",
                       help="Address to listen on (default 127.0.0.1: this machine only).")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--model", help="Model folder (default: $POLARIS_MODEL or ~/.polaris/models/current).")
    serve.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    serve.add_argument("--rules-only", action="store_true",
                       help="Don't load a model; only engine \"rules\" works.")
    serve.add_argument("--semgrep", "--semgrep-executable", dest="semgrep", type=Path,
                       help="Trusted absolute executable for the pinned optional analyzer.")
    serve.add_argument("--allow-temporary-analysis", action="store_true",
                       help="Explicitly permit isolated transient source files for workflow analysis; off by default.")
    serve.add_argument("--guard-policy", type=Path, help="Administrator-approved guard policy, fixed at startup.")
    serve.add_argument("--action-policy", type=Path,
                       help="Administrator-owned action policy; requests cannot supply policy.")
    serve.add_argument("--api-keys", type=Path, metavar="FILE",
                       help="Key file from `polaris serve keys create` (or set POLARIS_API_KEYS).")
    serve.add_argument("--rate-limit", type=float, metavar="PER_MINUTE",
                       help="Requests per minute per key (default: 60 with API keys, unlimited "
                            "without; 0 means unlimited).")
    serve.add_argument("--burst", type=int, default=30,
                       help="Requests a key may send at once before the rate limit applies.")
    serve.add_argument("--workers", type=int, default=1,
                       help="Reviews running at the same time (model reviews still take turns).")
    serve.add_argument("--queue", type=int, default=16,
                       help="Requests allowed to wait for a worker; more get 429 Too Many Requests.")
    serve.add_argument("--max-body-mb", type=float, default=5.0, help="Largest request body (default 5).")
    serve.add_argument("--max-files", type=int, default=500, help="Most files per review request.")
    serve.add_argument("--usage-log", type=Path, metavar="FILE",
                       help="Append usage records (counts only, never code) as JSON lines.")
    serve.add_argument("--cors-origin", action="append", default=[], metavar="ORIGIN",
                       help="Allow browser apps from this origin (repeatable). Off by default.")
    serve.add_argument("--docs", action="store_true",
                       help="Also serve interactive docs at /docs and /redoc (your browser loads "
                            "their scripts from a CDN).")
    tools = serve.add_subparsers(dest="serve_command", metavar="{keys,usage,openapi}")
    keys = tools.add_parser("keys", help="Create, list or revoke API keys (only salted hashes are stored).")
    actions = keys.add_subparsers(dest="keys_command", required=True)
    create = actions.add_parser("create", help="Create a key. It is shown once and never stored.")
    create.add_argument("--file", type=Path, required=True, help="Key file to create or update.")
    create.add_argument("--name", default="default", help="A label, for example a team or CI system.")
    create.add_argument("--rate-limit", dest="key_rate_limit", type=float, metavar="PER_MINUTE",
                        help="Per-minute limit for this key instead of the server's.")
    listing = actions.add_parser("list", help="List keys by name and ID.")
    listing.add_argument("--file", type=Path, required=True)
    revoke = actions.add_parser("revoke", help="Remove a key (restart the server to apply).")
    revoke.add_argument("--file", type=Path, required=True)
    revoke.add_argument("key_id")
    usage = tools.add_parser("usage", help="Totals per key from a --usage-log file.")
    usage.add_argument("log", type=Path)
    tools.add_parser("openapi", help="Print the API's OpenAPI description (for generating clients).")


def port_free(host: str, port: int) -> bool:
    try:
        family, _, _, _, address = socket.getaddrinfo(host.strip("[]"), port, type=socket.SOCK_STREAM)[0]
    except (OSError, IndexError):
        return False
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(address)
        except OSError:
            return False
    return True


def next_free_port(host: str, start: int) -> int | None:
    return next((port for port in range(start, min(start + 50, 65536)) if port_free(host, port)), None)


def _number_problem(args: argparse.Namespace) -> str | None:
    checks = (
        (1 <= args.port <= 65535, "--port must be between 1 and 65535."),
        (args.rate_limit is None or 0 <= args.rate_limit <= 100_000, "--rate-limit must be 0 or more."),
        (1 <= args.burst <= 10_000, "--burst must be between 1 and 10000."),
        (1 <= args.workers <= 64, "--workers must be between 1 and 64."),
        (0 <= args.queue <= 10_000, "--queue must be between 0 and 10000."),
        (0 < args.max_body_mb <= 100, "--max-body-mb must be above 0 and at most 100."),
        (1 <= args.max_files <= 100_000, "--max-files must be between 1 and 100000."),
    )
    return next((message for valid, message in checks if not valid), None)


def _load_keys(path: Path | None) -> KeyStore | None:
    from polaris.api.security import KeyProblem, KeyStore

    store = None
    if path is not None:
        store = KeyStore.read(path)
    elif os.environ.get("POLARIS_API_KEYS"):
        store = KeyStore.from_environment(os.environ["POLARIS_API_KEYS"])
    if store is not None and len(store) == 0:
        raise KeyProblem("The key file has no keys. Create one with `polaris serve keys create`.")
    return store


def _banner(settings: ApiSettings, service: ReviewService, keys: KeyStore | None) -> None:
    host = f"[{settings.host.strip('[]')}]" if ":" in settings.host else settings.host
    address = f"http://{host}:{settings.port}"
    lines = [
        f"Polaris API is running at {address}",
        f"  Model: {service.model_status().message}",
        f"  API keys: required ({len(keys)} configured)" if keys is not None
        else "  API keys: not required (this machine only)",
        f"  OpenAPI description: {address}/openapi.json"
        + (f" · interactive docs: {address}/docs" if settings.docs else ""),
        "  Submitted code is not persistently stored or logged.",
    ]
    if keys is not None and settings.host not in ("127.0.0.1", "localhost", "::1"):
        lines.append("  Put this behind a TLS reverse proxy before other machines use it (see docs/api.md).")
    lines.append("Keep this window open. Press Ctrl+C to stop.")
    print("\n".join(lines), flush=True)


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from polaris.api.app import REMOTE_NEEDS_KEYS, ApiSettings, create_app, is_loopback
    except ImportError:
        print(NEEDS_EXTRA, file=sys.stderr)
        return 2
    from polaris.api.security import KeyProblem
    from polaris.integrations import ReviewService
    from polaris.workflow.host import host_settings

    try:
        runtime, guard_policy, action_policy = host_settings(
            semgrep=args.semgrep, external=args.allow_temporary_analysis,
            guard_path=args.guard_policy, action_path=args.action_policy,
        )
    except ValueError:
        print("Polaris serve: invalid or unreadable trusted analyzer/policy configuration.", file=sys.stderr)
        return 2

    problem = _number_problem(args)
    if problem is not None:
        print(f"Polaris serve: {problem}", file=sys.stderr)
        return 2
    try:
        keys = _load_keys(args.api_keys)
    except KeyProblem as exc:
        print(f"Polaris serve: {exc}", file=sys.stderr)
        return 2
    if keys is None and not is_loopback(args.host):
        print(REMOTE_NEEDS_KEYS, file=sys.stderr)
        return 2
    if not port_free(args.host, args.port):
        suggestion = next_free_port(args.host, args.port + 1)
        hint = f" Try --port {suggestion}." if suggestion else ""
        print(f"Port {args.port} is already in use on {args.host}.{hint}", file=sys.stderr)
        return 2
    rate = args.rate_limit if args.rate_limit is not None else (60.0 if keys is not None else 0.0)
    settings = ApiSettings(
        host=args.host, port=args.port, max_body_bytes=int(args.max_body_mb * 1024 * 1024),
        max_files=args.max_files, rate_per_minute=rate, burst=args.burst, workers=args.workers,
        queue_depth=args.queue, cors_origins=tuple(args.cors_origin), docs=args.docs,
        usage_log=args.usage_log,
    )
    if args.rules_only:
        service = ReviewService(problem="not_requested")
    else:
        print("Polaris: loading the model (this happens once)...", file=sys.stderr, flush=True)
        service = ReviewService.load(args.model, device=args.device)
    try:
        app = create_app(
            service, settings=settings, keys=keys, analysis_runtime=runtime,
            guard_policy=guard_policy, action_policy=action_policy,
        )
    except (KeyProblem, ValueError) as exc:
        print(f"Polaris serve: {exc}", file=sys.stderr)
        return 2
    _banner(settings, service, keys)
    if args.allow_temporary_analysis:
        print("  Workflow analysis may use private temporary source files, removed after analysis.",
              file=sys.stderr, flush=True)
    # Access logs are off and nothing logs request bodies.
    uvicorn.run(app, host=args.host.strip("[]"), port=args.port, access_log=False,
                log_level="warning", proxy_headers=False, server_header=False)
    return 0


def _keys(args: argparse.Namespace) -> int:
    from polaris.api.security import KeyFile, KeyProblem, new_key, read_key_file, write_key_file

    try:
        if args.keys_command == "create":
            if not 1 <= len(args.name) <= 64:
                raise KeyProblem("--name must be 1 to 64 characters.")
            if args.key_rate_limit is not None and not 0 <= args.key_rate_limit <= 100_000:
                raise KeyProblem("--rate-limit must be 0 or more.")
            current = read_key_file(args.file) if args.file.exists() else KeyFile()
            raw, record = new_key(args.name, rate_per_minute=args.key_rate_limit)
            write_key_file(args.file, KeyFile(keys=[*current.keys, record]))
            print(f'New API key "{record.name}" (id {record.key_id}). It is shown only once; '
                  "store it in a secret manager now:")
            print(raw)
            print(f"Only a salted hash was saved to {args.file}.")
            print(f"Hash entry for POLARIS_API_KEYS: {record.key_id}:{record.salt}:{record.digest}")
            return 0
        stored = read_key_file(args.file)
        if args.keys_command == "list":
            if not stored.keys:
                print("No keys yet. Create one with `polaris serve keys create`.")
            for item in stored.keys:
                limit = f"  limit {item.rate_per_minute:g}/min" if item.rate_per_minute is not None else ""
                print(f"{item.key_id}  {item.name}  created {item.created}{limit}")
            return 0
        remaining = [item for item in stored.keys if item.key_id != args.key_id]
        if len(remaining) == len(stored.keys):
            raise KeyProblem(f"No key with id {args.key_id} in {args.file}.")
        write_key_file(args.file, KeyFile(keys=remaining))
        print(f"Revoked key {args.key_id}. Restart the server to apply it.")
        return 0
    except (KeyProblem, OSError) as exc:
        print(f"Polaris keys: {exc}", file=sys.stderr)
        return 2


def _usage(args: argparse.Namespace) -> int:
    from polaris.api.security import summarize_usage

    try:
        totals = summarize_usage(args.log)
    except (OSError, ValueError) as exc:
        print(f"Polaris usage: couldn't read {args.log} ({type(exc).__name__}).", file=sys.stderr)
        return 2
    if not totals:
        print("No usage recorded yet.")
        return 0
    columns = ("requests", "rejected", "reviews", "assessments", "files_reviewed",
               "functions_total", "functions_assessed")
    print("key       " + " ".join(f"{name:>18}" for name in columns))
    for key_id, counts in sorted(totals.items()):
        print(f"{key_id:<10}" + " ".join(f"{getattr(counts, name):>18}" for name in columns))
    return 0


def _openapi() -> int:
    try:
        from polaris.api.app import openapi_document
    except ImportError:
        print(NEEDS_EXTRA, file=sys.stderr)
        return 2
    print(json.dumps(openapi_document(), indent=2, sort_keys=True))
    return 0


def run(args: argparse.Namespace) -> int:
    if args.serve_command == "keys":
        return _keys(args)
    if args.serve_command == "usage":
        return _usage(args)
    if args.serve_command == "openapi":
        return _openapi()
    return _serve(args)

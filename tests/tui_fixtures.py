"""A deterministic sample repository and real Polaris reviews of it, for the `polaris tui` tests.

Commits use fixed dates, so commit IDs (and the HEAD shown in the trust bar) never change. Nothing
in the repository is executed; the reviews are the same static reviews `workflow review` runs.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

FILES_BASE = {
    "package.json": '{ "name": "sample", "private": true }\n',
    "tsconfig.json": '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
    "app/api/users/route.ts": 'export async function GET() {\n  return new Response("ok");\n}\n',
    "lib/run.ts": 'export const version = "1";\n',
    "scripts/deploy.py": 'def deploy():\n    return "ok"\n',
    ".github/workflows/triage.yml": (
        "name: triage\non: issues\npermissions:\n  contents: read\njobs:\n  label:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo \"triage\"\n"
    ),
    "Dockerfile": "FROM node:20@sha256:" + "0" * 64 + "\nUSER node\n",
    "cmd/tool/main.go": "package main\n\nfunc main() {}\n",
    "docs/notes.md": "# Notes\n",
}
FILES_FEATURE = {
    "app/api/users/route.ts": '''import { execFile } from "node:child_process";
import { db } from "@/lib/db";
import { runReport } from "@/lib/run";

export async function GET(request: Request) {
  const branch = new URL(request.url).searchParams.get("branch") ?? "main";
  execFile("git", ["log", branch], () => {});
  const target = new URL(request.url).searchParams.get("target");
  const response = await fetch(target!);
  return new Response(await response.text());
}

export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  await db.user.delete({ where: { id: id! } });
  return new Response(null, { status: 204 });
}

export async function POST(request: Request) {
  const body = await request.json();
  return runReport(body.name);
}
''',
    "lib/db.ts": "export const db: any = {};\n",
    "lib/run.ts": '''import { exec } from "node:child_process";

export function runReport(name: string) {
  exec("report --name " + name);
  return new Response("queued");
}
''',
    "app/components/Comment.tsx": '''export function Comment(props: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}
''',
    "scripts/deploy.py": '''import subprocess
import sys


def deploy(branch):
    subprocess.run(["git", "checkout", branch])


def main():
    deploy(sys.argv[1])
''',
    ".github/workflows/triage.yml": (
        "name: triage\non: issues\npermissions:\n  contents: read\njobs:\n  label:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo \"New issue ${{ github.event.issue.title }}\"\n"
    ),
    "Dockerfile": "FROM node:20\nRUN curl -fsSL https://example.com/install.sh | sh\n",
    "cmd/tool/main.go": 'package main\n\nimport "os/exec"\n\nfunc main() { exec.Command("sh", "-c", "echo hi").Run() }\n',
    "docs/notes.md": "# Notes\n\nReview the triage workflow.\n",
}


def git(root: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    return subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(root), *args],
                          check=True, capture_output=True, env=env).stdout.decode("utf-8").strip()


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def sample_repository(base: Path) -> Path:
    """`main` (safe files) and `feature` (checked out: the risky change), both committed."""
    root = base.resolve() / "sample"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(root, FILES_BASE)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "feature")
    write(root, FILES_FEATURE)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "feature")
    return root


def sarif_document() -> dict[str, Any]:
    def result(rule: str, level: str, text: str, uri: str, line: int) -> dict[str, Any]:
        return {"ruleId": rule, "level": level, "message": {"text": text},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}

    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep OSS", "version": "1.99.0", "rules": [
            {"id": "js.child-process", "properties": {"tags": ["CWE-78"], "security-severity": "8.0"}},
            {"id": "react.dangerously-set-inner-html", "properties": {"tags": ["CWE-79"], "security-severity": "5.0"}},
            {"id": "generic.pin-image", "properties": {"tags": ["maintainability"]}},
        ]}},
        "results": [
            result("js.child-process", "error", "child_process with an argument [red]markup[/red] \u202eevil",
                   "lib/run.ts", 4),
            result("react.dangerously-set-inner-html", "warning", "dangerouslySetInnerHTML with a non-constant value.",
                   "app/components/Comment.tsx", 2),
            result("generic.pin-image", "note", "Pin the base image to a digest.", "Dockerfile", 1),
            result("generic.pin-image", "note", "Outside the review.", "vendor/other.js", 1),
        ],
    }]}


def sarif_file(base: Path) -> Path:
    path = base.resolve() / "semgrep.sarif"
    path.write_text(json.dumps(sarif_document()), encoding="utf-8")
    return path


def tui_args(*argv: str) -> Any:
    from polaris import cli

    return cli.parser().parse_args(["tui", *argv])


def live_data(root: Path, *argv: str) -> Any:
    """A live review (as the worker runs it) of `root` with `polaris tui` arguments."""
    from polaris.tui.cli import prepare
    from polaris.tui.session import run_review

    data, request = prepare(tui_args("--root", str(root), "--no-external-analyzers", *argv))
    assert data is None and request is not None
    return run_review(request)


def fixed(data: Any, *, elapsed_ms: float = 123.0) -> Any:
    """The same review with a fixed elapsed time (for golden screenshots)."""
    from dataclasses import replace

    review = data.envelope.review
    summary = review.summary.model_copy(update={"elapsed_ms": elapsed_ms})
    envelope = data.envelope.model_copy(update={"review": review.model_copy(update={"summary": summary})})
    return replace(data, envelope=envelope, elapsed_s=elapsed_ms / 1000)


def screen_text(app: Any) -> str:
    """What the terminal shows right now, as plain text (no styles), from Textual's compositor."""
    import io

    from rich.console import Console

    width, height = app.size
    console = Console(width=width, height=height, record=True, file=io.StringIO(), color_system=None,
                      legacy_windows=False, force_terminal=True)
    console.print(app.screen._compositor.render_update(full=True, screen_stack=app._background_screens))
    return console.export_text()


async def settle(pilot: Any, app: Any, *, timeout: float = 30.0) -> None:
    """Wait until a live review worker has finished."""
    import asyncio
    import time

    deadline = time.monotonic() + timeout
    await pilot.pause()
    while app.running and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await pilot.pause()
    assert not app.running, "the review worker did not finish"


def saved_copy(data: Any, *, name: str = "sample.json", root: Path | None = None) -> Any:
    """The review as a saved report (no analyzed sources in memory)."""
    from polaris.tui.session import ReviewData

    return ReviewData(envelope=data.envelope, mode="saved", label="saved report", root=root or data.root,
                      elapsed_s=data.envelope.review.summary.elapsed_ms / 1000, report_name=name)

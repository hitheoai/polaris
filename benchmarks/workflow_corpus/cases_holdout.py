"""Held-out split: written before the corpus was first run and never used to change Polaris.

Different frameworks and code shapes than the development split (Sequelize, Pages Router,
server actions, FastAPI, Django, axum, rusqlite...). Report its numbers as measured; if an
analyzer change is ever made because of a case here, move that case to the dev split.

Moved to the dev split after analyzer fixes (2026-10-04), unchanged except for their ids:
ho-py-ssrf-fastapi-httpx, ho-py-path-pathlib and ho-rs-cmd-axum-query. The split measured
33/37 before those fixes.

The GitHub Actions and Dockerfile cases (ho-gha-*, ho-docker-*) were written on 2026-10-04,
before those two analyzers existed, from the rules' specification only.
"""

from typing import Any

from harness import Case


def case(id: str, check: str, expect: str, files: dict[str, str], *, language: str = "typescript",
         project: dict[str, Any] | None = None, note: str = "") -> Case:
    return Case(id=id, check=check, expect=expect, files=files, language=language,  # type: ignore[arg-type]
                project=project or {}, note=note, split="holdout")


EXPRESS = 'import express from "express";\nconst router = express.Router();\n'
# Non-working credential, assembled at runtime so the repository never holds the literal.
STRIPE_LIVE_HO = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcTyR8wKmX"

CASES = [
    # ---------------------------------------------------------------- TypeScript / JavaScript
    case("ho-ts-sql-sequelize-template", "sql_injection", "flagged", {"src/routes/users.ts": EXPRESS + r"""import { sequelize } from "../db";

router.get("/users/:id", async (req, res) => {
  const [rows] = await sequelize.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

export default router;
"""}),
    case("ho-ts-sql-sequelize-replacements", "sql_injection", "none", {"src/routes/users.ts": EXPRESS + r"""import { sequelize } from "../db";

router.get("/users/:id", async (req, res) => {
  const [rows] = await sequelize.query("SELECT * FROM users WHERE id = :id", { replacements: { id: req.params.id } });
  res.json(rows);
});

export default router;
"""}),
    case("ho-ts-sql-mysql2-placeholders", "sql_injection", "none", {"src/routes/tags.ts": EXPRESS + r"""import mysql from "mysql2/promise";
const connection = await mysql.createConnection(process.env.DATABASE_URL!);

router.get("/tags", async (req, res) => {
  const [rows] = await connection.execute("SELECT * FROM tags WHERE owner = ? AND name = ?", [req.query.owner, req.query.name]);
  res.json(rows);
});

export default router;
"""}),
    case("ho-ts-cmd-spawn-shell-option", "command_injection", "flagged", {"src/routes/export.ts": EXPRESS + r"""import { spawn } from "child_process";

router.post("/export", (req, res) => {
  const archive = req.body.name;
  spawn("zip", ["-r", archive, "exports/"], { shell: true });
  res.sendStatus(202);
});

export default router;
"""}),
    case("ho-ts-cmd-numeric-pid", "command_injection", "none", {"src/routes/processes.ts": EXPRESS + r"""import { exec } from "child_process";

router.post("/processes/stop", (req, res) => {
  const pid = parseInt(String(req.body.pid), 10);
  exec(`kill -TERM ${pid}`);
  res.sendStatus(204);
});

export default router;
"""}),
    case("ho-ts-code-vm-script", "code_injection", "flagged", {"app/api/sandbox/route.ts": r"""import vm from "node:vm";

export async function POST(request: Request) {
  const body = await request.json();
  const output = vm.runInNewContext(body.script, { Math });
  return Response.json({ output });
}
"""}),
    case("ho-ts-code-function-constant", "code_injection", "none", {"lib/math.ts": r"""
export const add = new Function("a", "b", "return a + b");
"""}),
    case("ho-ts-xss-insert-adjacent", "xss", "flagged", {"src/client/notice.ts": r"""
export function showNotice() {
  const message = decodeURIComponent(window.location.hash.slice(1));
  document.getElementById("notice")!.insertAdjacentHTML("beforeend", `<p>${message}</p>`);
}
"""}),
    case("ho-ts-xss-sanitize-html", "xss", "none", {"app/posts/[slug]/page.tsx": r"""import sanitizeHtml from "sanitize-html";
import { getPost } from "@/lib/posts";

export default async function Post({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = await getPost(slug);
  return <article dangerouslySetInnerHTML={{ __html: sanitizeHtml(post.html) }} />;
}
"""}),
    case("ho-ts-ssrf-got-base", "ssrf", "flagged", {"src/routes/health.ts": EXPRESS + r"""import got from "got";

router.get("/health/remote", async (req, res) => {
  const body = await got(`${req.query.base}/health`).text();
  res.send(body);
});

export default router;
"""}),
    case("ho-ts-ssrf-server-action", "ssrf", "flagged", {"app/feeds/actions.ts": r""""use server";

export async function importFeed(feedUrl: string) {
  const response = await fetch(feedUrl);
  return response.text();
}
"""}),
    case("ho-ts-ssrf-fixed-origin", "ssrf", "none", {"app/api/notify/route.ts": r"""
export async function POST(request: Request) {
  const { text } = await request.json();
  await fetch(`https://hooks.slack.com/services/${process.env.SLACK_WEBHOOK_PATH}`, {
    method: "POST", body: JSON.stringify({ text }),
  });
  return Response.json({ ok: true });
}
"""}),
    case("ho-ts-redirect-server-action", "open_redirect", "flagged", {"app/login/actions.ts": r""""use server";
import { redirect } from "next/navigation";

export async function finishLogin(formData: FormData) {
  const destination = String(formData.get("next") ?? "/");
  redirect(destination);
}
"""}),
    case("ho-ts-path-read-stream", "path_traversal", "flagged", {"src/routes/reports.ts": EXPRESS + r"""import fs from "fs";

router.get("/reports/:report", (req, res) => {
  fs.createReadStream(`/var/reports/${req.params.report}`).pipe(res);
});

export default router;
"""}),
    case("ho-ts-path-id-mapping", "path_traversal", "none", {"src/routes/legal.ts": EXPRESS + r"""
const FILES: Record<string, string> = { terms: "/srv/legal/terms.pdf", privacy: "/srv/legal/privacy.pdf" };

router.get("/legal/:id", (req, res) => {
  const file = FILES[req.params.id];
  if (!file) {
    return res.status(404).end();
  }
  res.sendFile(file);
});

export default router;
"""}),
    case("ho-ts-secret-github-token", "secret_exposure", "flagged", {"scripts/release.ts": r"""import { Octokit } from "@octokit/rest";

const octokit = new Octokit({ auth: "ghp_FAKEnotARealToken0123456789abcdefABCD" });
export default octokit;
"""}),
    case("ho-ts-secret-placeholder", "secret_exposure", "none", {"lib/config.example.ts": r"""
export const config = { apiKey: "your-api-key-here", region: "us-east-1" };
"""}),
    case("ho-ts-auth-pages-api-unguarded", "missing_authorization", "flagged", {"pages/api/admin/delete-user.ts": r"""import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "@/lib/prisma";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await prisma.user.delete({ where: { id: String(req.query.id) } });
  res.status(204).end();
}
"""}),
    case("ho-ts-auth-pages-api-guarded", "missing_authorization", "none", {"pages/api/admin/delete-user.ts": r"""import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.isAdmin) {
    return res.status(403).end();
  }
  await prisma.user.delete({ where: { id: String(req.query.id) } });
  res.status(204).end();
}
"""}),
    case("ho-ts-crypto-jwt-alg-none", "insecure_auth_crypto", "flagged", {"lib/verify.ts": r"""import jwt from "jsonwebtoken";

export function verify(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ["none", "HS256"] });
}
"""}),
    case("ho-ts-crypto-random-uuid", "insecure_auth_crypto", "none", {"lib/invite.ts": r"""import crypto from "crypto";

export function inviteToken() {
  const token = crypto.randomUUID();
  return token;
}
"""}),
    case("ho-ts-config-tls-env-off", "unsafe_security_configuration", "flagged", {"scripts/sync.ts": r"""
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

export async function sync() {
  await fetch("https://internal.example.com/sync");
}
"""}),
    # ---------------------------------------------------------------- Python
    case("ho-py-sql-django-raw", "sql_injection", "flagged", {"accounts/views.py": r"""from django.contrib.auth.models import User
from django.http import JsonResponse


def find_user(request):
    username = request.GET["username"]
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
    return JsonResponse({"count": len(list(users))})
"""}, language="python"),
    case("ho-py-sql-django-params", "sql_injection", "none", {"accounts/views.py": r"""from django.contrib.auth.models import User
from django.http import JsonResponse


def find_user(request):
    username = request.GET["username"]
    users = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
    return JsonResponse({"count": len(list(users))})
"""}, language="python"),
    case("ho-py-cmd-curl-option", "command_injection", "flagged", {"app/fetcher.py": r"""import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.post("/mirror")
def mirror():
    subprocess.run(["curl", "-sS", request.form["url"]], check=True)
    return "ok"
"""}, language="python"),
    case("ho-py-redirect-django", "open_redirect", "flagged", {"shop/views.py": r"""from django.http import HttpResponseRedirect


def after_checkout(request):
    return HttpResponseRedirect(request.GET["next"])
"""}, language="python"),
    case("ho-py-redirect-django-allowed-host", "open_redirect", "none", {"shop/views.py": r"""from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def after_checkout(request):
    next_url = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return HttpResponseRedirect(next_url)
"""}, language="python"),
    case("ho-py-code-exec", "code_injection", "flagged", {"app/admin.py": r"""from flask import Flask, request

app = Flask(__name__)


@app.post("/admin/run")
def run():
    exec(request.json["code"])
    return "done"
"""}, language="python"),
    case("ho-py-secret-django-key", "secret_exposure", "flagged", {"config/settings.py": r"""DEBUG = False
SECRET_KEY = "x9$Fq2!vL7zR@k4Nw8pT#c1mB6yH0dJs5gUe3aKo"
ALLOWED_HOSTS = ["example.com"]
"""}, language="python"),
    case("ho-py-auth-fastapi-missing", "missing_authorization", "flagged", {"app/routes.py": r"""from fastapi import FastAPI

from app.db import session

app = FastAPI()


@app.delete("/projects/{project_id}")
def delete_project(project_id: int):
    session.query(Project).filter(Project.id == project_id).delete()
    session.commit()
    return {"deleted": project_id}
"""}, language="python"),
    case("ho-py-auth-fastapi-depends", "missing_authorization", "none", {"app/routes.py": r"""from fastapi import Depends, FastAPI

from app.auth import get_current_user
from app.db import session

app = FastAPI()


@app.delete("/projects/{project_id}")
def delete_project(project_id: int, user=Depends(get_current_user)):
    session.query(Project).filter(Project.id == project_id, Project.owner_id == user.id).delete()
    session.commit()
    return {"deleted": project_id}
"""}, language="python"),
    # ---------------------------------------------------------------- Rust
    case("ho-rs-cmd-separator", "command_injection", "none", {"src-tauri/src/git.rs": r"""use std::process::Command;

#[tauri::command]
pub fn clone_repo(url: String) -> Result<(), String> {
    Command::new("git").arg("clone").arg("--").arg(&url).status().map_err(|e| e.to_string())?;
    Ok(())
}
"""}, language="rust"),
    case("ho-rs-sql-rusqlite-format", "sql_injection", "flagged", {"src-tauri/src/notes.rs": r"""use rusqlite::Connection;

#[tauri::command]
pub fn delete_note(id: String) -> Result<(), String> {
    let conn = Connection::open("notes.db").map_err(|e| e.to_string())?;
    conn.execute(&format!("DELETE FROM notes WHERE id = {}", id), []).map_err(|e| e.to_string())?;
    Ok(())
}
"""}, language="rust"),
    case("ho-rs-path-join", "path_traversal", "flagged", {"src-tauri/src/files.rs": r"""use std::path::Path;

#[tauri::command]
pub fn read_file(name: String) -> Result<Vec<u8>, String> {
    std::fs::read(Path::new("/srv/files").join(&name)).map_err(|e| e.to_string())
}
"""}, language="rust"),
    # ---------------------------------------------------------------- GitHub Actions workflows
    case("ho-gha-inject-issue-comment-body", "workflow_injection", "flagged", {".github/workflows/chatops.yml": r"""name: ChatOps
on:
  issue_comment:
    types: [created]

jobs:
  dispatch:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - name: Parse command
        id: parse
        run: |
          body="${{ github.event.comment.body }}"
          if [[ "$body" == /deploy* ]]; then
            echo "deploy=true" >> "$GITHUB_OUTPUT"
          fi
"""}, language="github_actions"),
    case("ho-gha-inject-prt-head-ref-folded", "workflow_injection", "flagged", {".github/workflows/announce.yml": r"""name: Announce
on:
  pull_request_target:
    branches: [main]

permissions:
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Announce
        run: >
          echo "Checking branch ${{ github.event.pull_request.head.ref }}
          from ${{ github.event.pull_request.head.repo.full_name }}"
"""}, language="github_actions"),
    case("ho-gha-inject-github-script-issue-title", "workflow_injection", "flagged", {".github/workflows/triage.yaml": r"""name: Triage new issues
on:
  issues:
    types: [opened, edited]

permissions:
  issues: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            const title = "${{ github.event.issue.title }}";
            if (/crash|panic/i.test(title)) {
              await github.rest.issues.addLabels({
                owner: context.repo.owner, repo: context.repo.repo,
                issue_number: context.issue.number, labels: ["bug"],
              });
            }
"""}, language="github_actions"),
    case("ho-gha-inject-workflow-run-branch", "workflow_injection", "flagged", {".github/workflows/coverage-comment.yml": r"""name: Coverage comment
on:
  workflow_run:
    workflows: ["Tests"]
    types: [completed]

jobs:
  comment:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - run: echo "Coverage for ${{ github.event.workflow_run.head_branch }}" >> "$GITHUB_STEP_SUMMARY"
"""}, language="github_actions"),
    case("ho-gha-inject-env-reexpanded", "workflow_injection", "flagged", {".github/workflows/pr-title.yml": r"""name: PR title
on: pull_request_target

jobs:
  lint-title:
    runs-on: ubuntu-latest
    env:
      PR_TITLE: ${{ github.event.pull_request.title }}
    steps:
      - name: Check conventional title
        run: |
          echo "Title: ${{ env.PR_TITLE }}"
          echo "$PR_TITLE" | grep -Eq '^(feat|fix|docs|chore)(\(.+\))?: '
"""}, language="github_actions"),
    case("ho-gha-inject-push-commit-message", "workflow_injection", "flagged", {".github/workflows/release-notes.yml": r"""name: Release notes
on:
  push:
    branches: [main]

jobs:
  notes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Skip marker
        run: |
          if echo "${{ github.event.head_commit.message }}" | grep -q '\[skip notes\]'; then
            exit 0
          fi
          ./scripts/release-notes.sh
"""}, language="github_actions"),
    case("ho-gha-inject-env-indirection", "workflow_injection", "none", {".github/workflows/welcome.yml": r"""name: Welcome
on:
  issues:
    types: [opened]

permissions:
  issues: write

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Greet the author
        env:
          GH_TOKEN: ${{ github.token }}
          TITLE: ${{ github.event.issue.title }}
          AUTHOR: ${{ github.event.issue.user.login }}
          NUMBER: ${{ github.event.issue.number }}
        run: |
          printf 'Thanks @%s for "%s"\n' "$AUTHOR" "$TITLE" > body.md
          gh issue comment "$NUMBER" --repo "$GITHUB_REPOSITORY" --body-file body.md
"""}, language="github_actions"),
    case("ho-gha-inject-numbers-and-shas", "workflow_injection", "none", {".github/workflows/size.yml": r"""name: Bundle size
on: pull_request_target

permissions:
  pull-requests: write

jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PR #${{ github.event.pull_request.number }} at ${{ github.event.pull_request.head.sha }}"
          echo "Opened by ${{ github.event.pull_request.user.login }} against ${{ github.event.pull_request.base.ref }}"
"""}, language="github_actions"),
    case("ho-gha-inject-boolean-expression", "workflow_injection", "none", {".github/workflows/retest.yml": r"""name: Retest
on:
  issue_comment:
    types: [created]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - id: cmd
        run: echo "retest=${{ startsWith(github.event.comment.body, '/retest') }}" >> "$GITHUB_OUTPUT"
      - if: steps.cmd.outputs.retest == 'true' && contains(github.event.comment.body, 'all')
        run: echo "Retesting everything"
"""}, language="github_actions"),
    case("ho-gha-checkout-prt-head-sha-npm", "untrusted_checkout", "flagged", {".github/workflows/preview.yml": r"""name: Preview build
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
        with:
          node-version: 20
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@6f51ac03b9356f520e9adb1b1b7802705f340c2b # v4.5.0
        with:
          name: site
          path: dist/
"""}, language="github_actions"),
    case("ho-gha-checkout-issue-comment-gh-pr", "untrusted_checkout", "flagged", {".github/workflows/ok-to-test.yml": r"""name: Integration tests on request
on:
  issue_comment:
    types: [created]

jobs:
  integration:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Check out the pull request
        env:
          GH_TOKEN: ${{ github.token }}
          PR: ${{ github.event.issue.number }}
        run: gh pr checkout "$PR"
      - name: Integration tests
        env:
          API_TOKEN: ${{ secrets.INTEGRATION_API_TOKEN }}
        run: make integration-test
"""}, language="github_actions"),
    case("ho-gha-checkout-workflow-run-head-sha", "untrusted_checkout", "flagged", {".github/workflows/lint-report.yml": r"""name: Lint report
on:
  workflow_run:
    workflows: [CI]
    types: [completed]

permissions:
  checks: write
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - name: Lint
        run: ./gradlew spotlessCheck --no-daemon
"""}, language="github_actions"),
    case("ho-gha-checkout-prt-base-only", "untrusted_checkout", "none", {".github/workflows/pr-labels.yml": r"""name: PR labels
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: npm ci --ignore-scripts
      - run: node scripts/label-pr.js
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
"""}, language="github_actions"),
    case("ho-gha-checkout-prt-merged-release", "untrusted_checkout", "none", {".github/workflows/publish-on-merge.yml": r"""name: Publish on merge
on:
  pull_request_target:
    types: [closed]
    branches: [main]

permissions:
  contents: read

jobs:
  publish:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.merge_commit_sha }}
      - run: npm ci && npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
"""}, language="github_actions"),
    case("ho-gha-checkout-pull-request-head", "untrusted_checkout", "none", {".github/workflows/test.yml": r"""name: Test
on:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""}, language="github_actions"),
    case("ho-gha-checkout-same-repo-guard", "untrusted_checkout", "none", {".github/workflows/e2e.yml": r"""name: E2E with secrets
on:
  pull_request_target:

jobs:
  e2e:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run e2e
        env:
          E2E_PASSWORD: ${{ secrets.E2E_PASSWORD }}
"""}, language="github_actions"),
    case("ho-gha-unpinned-third-party-tag", "unpinned_dependency", "flagged", {".github/workflows/docs.yml": r"""name: Docs
on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install mkdocs-material && mkdocs build
      - uses: peaceiris/actions-gh-pages@v4
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./site
"""}, language="github_actions"),
    case("ho-gha-unpinned-sha-pinned", "unpinned_dependency", "none", {".github/workflows/image.yml": r"""name: Image
on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  packages: write

jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: docker/setup-buildx-action@c47758b77c9736f4b2ef4073d4d51994fabfe349 # v3.7.1
      - uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75 # v6.9.0
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
"""}, language="github_actions"),
    case("ho-gha-unpinned-first-party-and-local", "unpinned_dependency", "none", {".github/workflows/codeql.yml": r"""name: CodeQL
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-toolchain
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/analyze@v3
"""}, language="github_actions"),
    case("ho-gha-perms-write-all-prt", "excessive_privileges", "flagged", {".github/workflows/labeler.yml": r"""name: Labeler
on: [pull_request_target]

permissions: write-all

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9 # v5.0.0
"""}, language="github_actions"),
    case("ho-gha-perms-narrow-prt", "excessive_privileges", "none", {".github/workflows/stale-labels.yml": r"""name: Size labels
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  size:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: codelytv/pr-size-labeler@c7a55a022747628b50f3eb5bf863b9e796b8f274 # v1.10.1
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""}, language="github_actions"),
    case("ho-gha-secret-echo-base64", "secret_exposure", "flagged", {".github/workflows/deploy.yml": r"""name: Deploy
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      KUBECONFIG_DATA: ${{ secrets.KUBECONFIG }}
    steps:
      - name: Debug credentials
        run: |
          echo "kubeconfig:"
          echo "$KUBECONFIG_DATA" | base64
"""}, language="github_actions"),
    case("ho-gha-secret-docker-login-stdin", "secret_exposure", "none", {".github/workflows/push-image.yml": r"""name: Push image
on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  push:
    runs-on: ubuntu-latest
    steps:
      - name: Log in
        env:
          REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
"""}, language="github_actions"),
    case("ho-gha-secret-add-mask", "secret_exposure", "none", {".github/workflows/session.yml": r"""name: Session
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  session:
    runs-on: ubuntu-latest
    steps:
      - name: Mask the session token
        env:
          SESSION_TOKEN: ${{ secrets.SESSION_TOKEN }}
        run: |
          echo "::add-mask::$SESSION_TOKEN"
          ./bin/start-session --token-file <(printf '%s' "$SESSION_TOKEN")
"""}, language="github_actions"),
    case("ho-gha-curl-pipe-bash-http", "unverified_download", "flagged", {".github/workflows/tools.yml": r"""name: Tools
on: [push]

permissions:
  contents: read

jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - name: Install the CLI
        run: curl -sL http://get.example-cli.dev/install.sh | sudo bash -s -- --version 2.1.0
      - run: example-cli check
"""}, language="github_actions"),
    case("ho-gha-download-verified", "unverified_download", "none", {".github/workflows/lint.yml": r"""name: Lint
on: [pull_request]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    env:
      TOOL_SHA256: 2f1a1e3c7d5b9a0e8c4f6b2d1a3e5c7b9d0f2e4a6c8b0d2f4e6a8c0b2d4f6e8a
    steps:
      - run: |
          curl -fsSLo /tmp/tool.tar.gz https://github.com/example/tool/releases/download/v1.4.0/tool-linux-amd64.tar.gz
          echo "$TOOL_SHA256  /tmp/tool.tar.gz" | sha256sum -c -
          tar -xzf /tmp/tool.tar.gz -C /usr/local/bin tool
          tool lint .
"""}, language="github_actions"),
    case("ho-gha-download-pipe-to-tar", "unverified_download", "none", {".github/workflows/bench.yml": r"""name: Bench
on: [pull_request]

permissions:
  contents: read

jobs:
  bench:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://github.com/example/bench/releases/download/v0.9.1/bench.tar.gz | tar -xz -C "$RUNNER_TEMP"
      - run: '"$RUNNER_TEMP/bench" run'
"""}, language="github_actions"),
    # ---------------------------------------------------------------- Dockerfiles
    case("ho-docker-nodesource-continuation", "unverified_download", "flagged", {"Dockerfile": r"""FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 # Node.js from the vendor's setup script
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
USER node
CMD ["node", "server.js"]
"""}, language="dockerfile"),
    case("ho-docker-heredoc-wget-sh", "unverified_download", "flagged", {"docker/tools.Dockerfile": r"""# syntax=docker/dockerfile:1.7
FROM alpine:3.20
RUN <<EOF
set -eux
apk add --no-cache wget
wget -qO- http://downloads.example.org/agent/install.sh | sh -s -- --no-service
EOF
USER 65534
"""}, language="dockerfile"),
    case("ho-docker-windows-escape-directive", "unverified_download", "flagged", {"windows/Dockerfile": r"""# escape=`
FROM mcr.microsoft.com/windows/servercore:ltsc2022
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"]
RUN Set-ExecutionPolicy Bypass -Scope Process -Force; `
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
RUN choco install -y git
USER ContainerUser
"""}, language="dockerfile"),
    case("ho-docker-add-remote-binary", "unverified_download", "flagged", {"build/Dockerfile.ci": r"""FROM ubuntu:24.04
ADD https://github.com/mikefarah/yq/releases/download/v4.44.3/yq_linux_amd64 /usr/local/bin/yq
RUN chmod +x /usr/local/bin/yq && useradd -m ci
USER ci
"""}, language="dockerfile"),
    case("ho-docker-add-with-checksum", "unverified_download", "none", {"Dockerfile": r"""# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04
ADD --checksum=sha256:0e7d0c5b2a64b8e0a0f1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708 \
    https://github.com/mikefarah/yq/releases/download/v4.44.3/yq_linux_amd64 /usr/local/bin/yq
RUN chmod +x /usr/local/bin/yq
USER 1000
"""}, language="dockerfile"),
    case("ho-docker-download-then-verify", "unverified_download", "none", {"Dockerfile": r"""FROM ubuntu:24.04
ARG INSTALLER_SHA256=6c2f8a5d1e4b7a9c0d3e6f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c
RUN curl -fsSLo /tmp/install.sh https://get.example.dev/install.sh \
 && echo "${INSTALLER_SHA256}  /tmp/install.sh" | sha256sum -c - \
 && sh /tmp/install.sh \
 && rm /tmp/install.sh
USER 1000
"""}, language="dockerfile"),
    case("ho-docker-curl-pipe-jq", "unverified_download", "none", {"Dockerfile": r"""FROM alpine:3.20
RUN apk add --no-cache curl jq \
 && curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name > /etc/gh-version
USER 65534
"""}, language="dockerfile"),
    case("ho-docker-quoted-pipe-in-docs", "unverified_download", "none", {"Dockerfile": r"""FROM alpine:3.20
# Never do this in production: curl https://get.example.dev | sh
RUN mkdir -p /usr/share/doc/app \
 && echo "Install with: curl -fsSL https://get.example.dev | sh" > /usr/share/doc/app/INSTALL.txt
USER 65534
"""}, language="dockerfile"),
    case("ho-docker-env-live-key", "secret_exposure", "flagged", {"Dockerfile": f"""FROM node:20-alpine
WORKDIR /srv
ENV NODE_ENV=production \\
    STRIPE_SECRET_KEY={STRIPE_LIVE_HO}
COPY . .
RUN npm ci --omit=dev
USER node
CMD ["node", "index.js"]
"""}, language="dockerfile"),
    case("ho-docker-arg-token-final-stage", "secret_exposure", "flagged", {"Dockerfile": r"""FROM node:20-bookworm-slim
ARG NPM_TOKEN
WORKDIR /app
COPY package.json package-lock.json ./
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc && npm ci && rm -f .npmrc
COPY . .
USER node
CMD ["npm", "start"]
"""}, language="dockerfile"),
    case("ho-docker-secret-mount", "secret_exposure", "none", {"Dockerfile": r"""# syntax=docker/dockerfile:1.10
FROM node:20-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN \
    npm ci --omit=dev
COPY . .
USER node
CMD ["npm", "start"]
"""}, language="dockerfile"),
    case("ho-docker-public-gpg-key", "secret_exposure", "none", {"Dockerfile": r"""FROM buildpack-deps:bookworm
ENV GPG_KEY 7169605F62C751356D054A26A821E680E5FA6305
ENV PYTHON_VERSION 3.13.0
RUN set -eux; \
    wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \
    wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; \
    gpg --batch --verify python.tar.xz.asc python.tar.xz
USER 1000
"""}, language="dockerfile"),
    case("ho-docker-root-after-user", "excessive_privileges", "flagged", {"Dockerfile": r"""FROM python:3.12-slim AS base
RUN useradd --create-home app
USER app
WORKDIR /home/app
COPY --chown=app requirements.txt .
RUN pip install --user -r requirements.txt

FROM base AS runtime
COPY --chown=app . .
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 && rm -rf /var/lib/apt/lists/*
CMD ["python", "-m", "app"]
"""}, language="dockerfile"),
    case("ho-docker-no-user-gunicorn", "excessive_privileges", "flagged", {"services/api/Dockerfile": r"""FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:create_app()"]
"""}, language="dockerfile"),
    case("ho-docker-numeric-user", "excessive_privileges", "none", {"Dockerfile": r"""FROM node:20-alpine
WORKDIR /app
COPY --chown=10001:10001 . .
RUN npm ci --omit=dev
USER 10001:10001
CMD ["node", "server.js"]
"""}, language="dockerfile"),
    case("ho-docker-user-inherited-from-stage", "excessive_privileges", "none", {"Dockerfile": r"""FROM node:20-slim AS base
WORKDIR /home/node/app
USER node

FROM base AS deps
COPY --chown=node package*.json ./
RUN npm ci

FROM deps AS app
COPY --chown=node . .
CMD ["node", "index.js"]
"""}, language="dockerfile"),
    case("ho-docker-gosu-entrypoint", "excessive_privileges", "none", {"Dockerfile": r"""FROM debian:bookworm-slim
RUN groupadd -r app && useradd -r -g app app \
 && apt-get update && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/*
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["app-server"]
"""}, language="dockerfile"),
    case("ho-docker-unpinned-multistage", "unpinned_dependency", "flagged", {"Containerfile": r"""FROM --platform=$BUILDPLATFORM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
"""}, language="dockerfile"),
    case("ho-docker-digest-pinned-stages", "unpinned_dependency", "none", {"Dockerfile": r"""FROM golang:1.23-alpine@sha256:9a425d78a8257fc92d41ad979d38cb54005bac3fdefbdadde868e004eccbb898 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app ./cmd/app

FROM scratch
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
"""}, language="dockerfile"),
    case("ho-docker-arg-parameterized-base", "unpinned_dependency", "none", {"Dockerfile": r"""ARG BASE_IMAGE=ubuntu:24.04
ARG RUNTIME_IMAGE
FROM ${BASE_IMAGE} AS build
RUN apt-get update && apt-get install -y build-essential && make -C /src

FROM $RUNTIME_IMAGE
COPY --from=build /src/out /opt/app
USER 1000
"""}, language="dockerfile"),
]

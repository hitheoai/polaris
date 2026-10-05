"""Development split: used while building and tuning the analyzers (numbers are optimistic).

Every check has vulnerable cases and safe code that looks similar. Paths follow framework
conventions (app/api/*/route.ts, pages, server actions, Express routers, Tauri commands)
because entry-point detection depends on them. Fake credentials are deliberately non-working.
"""

from typing import Any

from harness import Case


def case(id: str, check: str, expect: str, files: dict[str, str], *, language: str = "typescript",
         project: dict[str, Any] | None = None, note: str = "", line: int | None = None) -> Case:
    return Case(id=id, check=check, expect=expect, files=files, language=language,  # type: ignore[arg-type]
                project=project or {}, note=note, split="dev", line=line)


NEXT = 'import { NextRequest, NextResponse } from "next/server";\n'
EXPRESS = 'import express from "express";\nconst router = express.Router();\n'
# Realistic-looking but non-working credentials, assembled at runtime so the repository itself
# never contains a complete credential-shaped literal.
STRIPE_LIVE = "sk_" + "live_" + "51Hq2xZ7aKcV9mRtY3pWnB8dL4eF6gJ0"
AWS_KEY_ID = "AKIA" + "Q7V3XK2NR5TBWJ4M"
GITHUB_PAT = "ghp_" + "R7vK2mQ9xL4tN8wB3cJ6hD1fG5sA0pE2yU9i"
# A full commit pin, as GitHub's own hardening guide recommends.
CHECKOUT = "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7"

CASES = [
    # ---------------------------------------------------------------- SQL injection (TS)
    case("ts-sql-prisma-unsafe", "sql_injection", "flagged", {"app/api/users/route.ts": NEXT + r"""import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const email = request.nextUrl.searchParams.get("email");
  const users = await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);
  return NextResponse.json(users);
}
"""}),
    case("ts-sql-pg-template", "sql_injection", "flagged", {"src/routes/orders.ts": EXPRESS + r"""import { Pool } from "pg";
const pool = new Pool();

router.get("/orders", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM orders WHERE customer = '${req.query.customer}'`);
  res.json(rows);
});

export default router;
"""}),
    case("ts-sql-knex-raw", "sql_injection", "flagged", {"src/routes/products.ts": EXPRESS + r"""import { db } from "../db";

router.get("/products", async (req, res) => {
  const name = String(req.query.name);
  const rows = await db("products").whereRaw("name = '" + name + "'");
  res.json(rows);
});

export default router;
"""}),
    case("ts-sql-prisma-tagged", "sql_injection", "none", {"app/api/users/route.ts": NEXT + r"""import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const email = request.nextUrl.searchParams.get("email");
  const users = await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
  return NextResponse.json(users);
}
"""}),
    case("ts-sql-pg-params", "sql_injection", "none", {"src/routes/orders.ts": EXPRESS + r"""import { Pool } from "pg";
const pool = new Pool();

router.get("/orders", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM orders WHERE customer = $1", [req.query.customer]);
  res.json(rows);
});

export default router;
"""}),
    case("ts-sql-drizzle-builder", "sql_injection", "none", {"app/api/accounts/route.ts": NEXT + r"""import { eq } from "drizzle-orm";
import { db } from "@/db";
import { accounts } from "@/db/schema";

export async function GET(request: NextRequest) {
  const email = request.nextUrl.searchParams.get("email") ?? "";
  const rows = await db.select().from(accounts).where(eq(accounts.email, email));
  return NextResponse.json(rows);
}
"""}),
    # ---------------------------------------------------------------- command injection (TS)
    case("ts-cmd-exec-template", "command_injection", "flagged", {"app/api/git/log/route.ts": NEXT + r"""import { exec } from "child_process";

export async function POST(request: NextRequest) {
  const { branch } = await request.json();
  exec(`git log --oneline ${branch}`, (error, stdout) => console.log(stdout));
  return NextResponse.json({ ok: true });
}
"""}),
    case("ts-cmd-execsync-concat", "command_injection", "flagged", {"src/routes/images.ts": EXPRESS + r"""import { execSync } from "node:child_process";

router.post("/thumbnail", (req, res) => {
  execSync("convert " + req.body.file + " -resize 200x200 thumb.png");
  res.sendStatus(204);
});

export default router;
"""}),
    case("ts-cmd-execfile-option-injection", "command_injection", "flagged", {"app/api/import/route.ts": NEXT + r"""import { execFile } from "child_process";

export async function POST(request: NextRequest) {
  const { repoUrl } = await request.json();
  execFile("git", ["clone", repoUrl, "/srv/imports/repo"], () => {});
  return NextResponse.json({ started: true });
}
"""}),
    case("ts-cmd-execfile-separator", "command_injection", "none", {"app/api/import/route.ts": NEXT + r"""import { execFile } from "child_process";

export async function POST(request: NextRequest) {
  const { repoUrl } = await request.json();
  execFile("git", ["clone", "--", repoUrl, "/srv/imports/repo"], () => {});
  return NextResponse.json({ started: true });
}
"""}),
    case("ts-cmd-spawn-fixed", "command_injection", "none", {"src/routes/status.ts": EXPRESS + r"""import { spawn } from "child_process";

router.get("/disk", (_req, res) => {
  const child = spawn("df", ["-h", "/srv/data"]);
  child.stdout.pipe(res);
});

export default router;
"""}),
    case("ts-cmd-allowlisted-subcommand", "command_injection", "none", {"app/api/git/route.ts": NEXT + r"""import { execFile } from "child_process";

const ALLOWED = new Set(["status", "log", "branch"]);

export async function POST(request: NextRequest) {
  const { command } = await request.json();
  if (!ALLOWED.has(command)) {
    return NextResponse.json({ error: "not allowed" }, { status: 400 });
  }
  execFile("git", [command], () => {});
  return NextResponse.json({ ok: true });
}
"""}),
    # ---------------------------------------------------------------- code injection (TS)
    case("ts-code-eval", "code_injection", "flagged", {"app/api/calc/route.ts": NEXT + r"""
export async function POST(request: NextRequest) {
  const { expression } = await request.json();
  const result = eval(expression);
  return NextResponse.json({ result });
}
"""}),
    case("ts-code-new-function", "code_injection", "flagged", {"src/routes/rules.ts": EXPRESS + r"""
router.post("/rules/test", (req, res) => {
  const rule = new Function("order", req.body.code);
  res.json({ matches: rule({ total: 10 }) });
});

export default router;
"""}),
    case("ts-code-json-parse", "code_injection", "none", {"app/api/calc/route.ts": NEXT + r"""
export async function POST(request: NextRequest) {
  const raw = await request.text();
  const data = JSON.parse(raw);
  return NextResponse.json({ keys: Object.keys(data) });
}
"""}),
    case("ts-code-settimeout-callback", "code_injection", "none", {"app/api/jobs/route.ts": NEXT + r"""import { refresh } from "@/lib/jobs";

export async function POST(request: NextRequest) {
  const { id } = await request.json();
  setTimeout(() => refresh(id), 1000);
  return NextResponse.json({ queued: true });
}
"""}),
    # ---------------------------------------------------------------- XSS (TS/React)
    case("ts-xss-dangerously-search-param", "xss", "flagged", {"app/search/page.tsx": r"""
export default async function SearchPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q } = await searchParams;
  return <div dangerouslySetInnerHTML={{ __html: `Results for <b>${q}</b>` }} />;
}
"""}),
    case("ts-xss-express-html", "xss", "flagged", {"src/routes/hello.ts": EXPRESS + r"""
router.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

export default router;
"""}),
    case("ts-xss-client-innerhtml", "xss", "flagged", {"components/Banner.tsx": r""""use client";
import { useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";

export function Banner() {
  const params = useSearchParams();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.innerHTML = params.get("message") ?? "";
  }, [params]);
  return <div ref={ref} />;
}
"""}),
    case("ts-xss-dompurify", "xss", "none", {"app/search/page.tsx": r"""import DOMPurify from "isomorphic-dompurify";

export default async function SearchPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q } = await searchParams;
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(`Results for <b>${q}</b>`) }} />;
}
"""}),
    case("ts-xss-react-text", "xss", "none", {"app/search/page.tsx": r"""
export default async function SearchPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q } = await searchParams;
  return <p>Results for <b>{q}</b></p>;
}
"""}),
    case("ts-xss-textcontent", "xss", "none", {"components/Banner.tsx": r""""use client";
import { useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";

export function Banner() {
  const params = useSearchParams();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.textContent = params.get("message") ?? "";
  }, [params]);
  return <div ref={ref} />;
}
"""}),
    # ---------------------------------------------------------------- SSRF (TS)
    case("ts-ssrf-fetch-query", "ssrf", "flagged", {"app/api/preview/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get("url");
  const response = await fetch(url!);
  return new NextResponse(await response.text());
}
"""}),
    case("ts-ssrf-axios-body", "ssrf", "flagged", {"src/routes/webhooks.ts": EXPRESS + r"""import axios from "axios";

router.post("/webhooks/test", async (req, res) => {
  const result = await axios.get(req.body.webhookUrl);
  res.json({ status: result.status });
});

export default router;
"""}),
    case("ts-ssrf-through-helper", "ssrf", "flagged", {
        "app/api/unfurl/route.ts": NEXT + r"""import { loadPage } from "@/lib/unfurl";

export async function POST(request: NextRequest) {
  const { link } = await request.json();
  const html = await loadPage(link);
  return NextResponse.json({ size: html.length });
}
""",
        "src/lib/unfurl.ts": r"""export async function loadPage(target: string) {
  const response = await fetch(target, { redirect: "follow" });
  return response.text();
}
"""}, note="Sink in an imported helper (related context)."),
    case("ts-ssrf-fixed-host", "ssrf", "none", {"app/api/repos/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  const owner = request.nextUrl.searchParams.get("owner") ?? "";
  const repo = request.nextUrl.searchParams.get("repo") ?? "";
  const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
  return NextResponse.json(await response.json());
}
"""}),
    case("ts-ssrf-host-allowlist", "ssrf", "none", {"app/api/preview/route.ts": NEXT + r"""
const ALLOWED_HOSTS = new Set(["images.example.com", "cdn.example.com"]);

export async function GET(request: NextRequest) {
  const raw = request.nextUrl.searchParams.get("url") ?? "";
  const target = new URL(raw);
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    return NextResponse.json({ error: "host not allowed" }, { status: 400 });
  }
  const response = await fetch(target);
  return new NextResponse(await response.arrayBuffer());
}
"""}),
    case("ts-ssrf-env-base", "ssrf", "none", {"app/api/items/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id");
  const response = await fetch(`${process.env.INVENTORY_API_URL}/items/${encodeURIComponent(id ?? "")}`);
  return NextResponse.json(await response.json());
}
"""}),
    # SSRF shapes seen while triaging a large Next.js app (OpenCharts full scan).
    case("ts-ssrf-wrapper-fixed-origin", "ssrf", "none", {
        "app/api/bible/route.ts": NEXT + r"""import { getChapter } from "@/lib/bible";

export async function GET(request: NextRequest) {
  const book = request.nextUrl.searchParams.get("book") ?? "GEN";
  const chapter = request.nextUrl.searchParams.get("chapter") ?? "1";
  return NextResponse.json(await getChapter(book, chapter));
}
""",
        "src/lib/bible.ts": r"""const BASE = "https://bible.helloao.org";

async function fetchJson(url: string) {
  const res = await fetch(url);
  return res.json();
}

export async function getChapter(book: string, chapter: string) {
  return fetchJson(`${BASE}/api/BSB/${encodeURIComponent(book)}/${chapter}.json`);
}
"""}, note="The caller fixes the origin before the wrapper's fetch(url)."),
    case("ts-ssrf-own-origin", "ssrf", "none", {"app/api/admin/warmup/route.ts": NEXT + r"""
export async function POST(request: NextRequest) {
  const baseUrl = request.nextUrl.origin;
  const res = await fetch(`${baseUrl}/api/health`);
  return NextResponse.json({ ok: res.ok });
}
"""}, note="The deployment's own origin is not attacker input."),
    case("ts-ssrf-db-lookup-by-id", "ssrf", "none", {
        "app/api/hooks/[id]/test/route.ts": NEXT + r"""import { getWebhook } from "@/services/hooks";

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const hook = await getWebhook(id);
  await fetch(hook.url, { method: "POST" });
  return NextResponse.json({ ok: true });
}
""",
        "src/services/hooks.ts": r"""import { databases } from "@/lib/appwrite";

export async function getWebhook(id: string) {
  const doc = await databases.getDocument("db", "webhooks", id);
  return parseHook(doc);
}

function parseHook(doc: Record<string, unknown>) {
  return { url: String(doc.url), id: String(doc.$id) };
}
"""}, note="A record looked up by id is stored data, not the request value."),
    case("ts-ssrf-guard-call", "ssrf", "none", {"app/api/preview/route.ts": NEXT + r"""import { checkFetchUrlSafe } from "@/lib/ssrfGuard";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const url = String(body.url ?? "");
  const safe = await checkFetchUrlSafe(url);
  if (!safe.ok) return NextResponse.json({ error: "blocked" }, { status: 400 });
  const res = await fetch(url);
  return new NextResponse(await res.text());
}
"""}),
    case("ts-ssrf-host-guard-call", "ssrf", "none", {"app/api/logo/route.ts": NEXT + r"""import { isDnsResolvedPublic, isPrivateHostname } from "@/lib/ssrfGuard";

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get("url") ?? "";
  const parsed = new URL(url);
  if (isPrivateHostname(parsed.hostname) || !(await isDnsResolvedPublic(parsed.hostname))) {
    return NextResponse.json({ error: "blocked" }, { status: 403 });
  }
  const res = await fetch(url);
  return new NextResponse(res.body);
}
"""}),
    case("ts-ssrf-incomplete-denylist", "ssrf", "flagged", {"app/api/brand/asset/route.ts": NEXT + r"""
export async function POST(request: NextRequest) {
  const body = await request.json();
  const parsed = new URL(String(body.url));
  if (parsed.hostname.match(/^(10\.|192\.168\.)/) || parsed.hostname.endsWith(".local")) {
    return NextResponse.json({ error: "Internal URLs are not allowed" }, { status: 400 });
  }
  const upstream = await fetch(String(body.url));
  return new NextResponse(upstream.body);
}
"""}, note="A partial hostname denylist (localhost, 127.x, 169.254.x still reachable) is not a guard."),
    case("ts-ssrf-persist-remote-url", "ssrf", "flagged", {"app/api/chat-image/persist/route.ts": NEXT + r"""
export async function POST(request: NextRequest) {
  const { dataUri } = await request.json();
  let bytes: ArrayBuffer;
  if (dataUri.startsWith("data:")) {
    bytes = Buffer.from(dataUri.split(",")[1], "base64").buffer;
  } else {
    const res = await fetch(dataUri);
    bytes = await res.arrayBuffer();
  }
  return NextResponse.json({ size: bytes.byteLength });
}
"""}, note="Anything that isn't a data: URI is fetched from wherever the caller points."),
    # ---------------------------------------------------------------- open redirect (TS)
    case("ts-redirect-nextresponse", "open_redirect", "flagged", {"app/auth/callback/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  const next = request.nextUrl.searchParams.get("next") ?? "/";
  return NextResponse.redirect(new URL(next, request.url));
}
"""}),
    case("ts-redirect-express", "open_redirect", "flagged", {"src/routes/login.ts": EXPRESS + r"""
router.get("/login/done", (req, res) => {
  res.redirect(String(req.query.returnTo));
});

export default router;
"""}),
    case("ts-redirect-page", "open_redirect", "flagged", {"app/go/page.tsx": r"""import { redirect } from "next/navigation";

export default async function Go({ searchParams }: { searchParams: Promise<{ to?: string }> }) {
  const { to } = await searchParams;
  redirect(to ?? "/");
}
"""}),
    case("ts-redirect-relative-check", "open_redirect", "none", {"app/auth/callback/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  const next = request.nextUrl.searchParams.get("next") ?? "/";
  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  return NextResponse.redirect(new URL(safe, request.url));
}
"""}),
    case("ts-redirect-allowlist-exit", "open_redirect", "none", {"app/login/actions.ts": r""""use server";
import { redirect } from "next/navigation";

const DESTINATIONS = ["/dashboard", "/settings", "/billing"];

export async function finishLogin(formData: FormData) {
  const requested = String(formData.get("next") ?? "/dashboard");
  if (!DESTINATIONS.includes(requested)) {
    redirect("/dashboard");
  }
  redirect(requested);
}
"""}, note="Moved from the holdout split after its first run: redirect() in a guard block is an exit."),
    case("ts-redirect-set-allowlist", "open_redirect", "none", {"app/login/actions.ts": r""""use server";
import { redirect } from "next/navigation";

const DESTINATIONS = ["/dashboard", "/settings"];

export async function finishLogin(formData: FormData) {
  const requested = String(formData.get("next") ?? "/dashboard");
  if (!new Set(DESTINATIONS).has(requested)) {
    return redirect("/dashboard");
  }
  redirect(requested);
}
"""}),
    case("ts-redirect-fixed", "open_redirect", "none", {"app/logout/route.ts": NEXT + r"""
export async function GET(request: NextRequest) {
  return NextResponse.redirect(new URL("/login", request.url));
}
"""}),
    # ---------------------------------------------------------------- path traversal (TS)
    case("ts-path-join-query", "path_traversal", "flagged", {"src/routes/files.ts": EXPRESS + r"""import fs from "fs/promises";
import path from "path";

const UPLOADS = "/srv/uploads";

router.get("/files", async (req, res) => {
  const data = await fs.readFile(path.join(UPLOADS, String(req.query.name)));
  res.send(data);
});

export default router;
"""}),
    case("ts-path-route-param", "path_traversal", "flagged", {"app/api/docs/[slug]/route.ts": NEXT + r"""import { readFile } from "fs/promises";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const markdown = await readFile(`content/docs/${slug}.md`, "utf8");
  return new NextResponse(markdown);
}
"""}),
    case("ts-path-basename", "path_traversal", "none", {"src/routes/files.ts": EXPRESS + r"""import fs from "fs/promises";
import path from "path";

const UPLOADS = "/srv/uploads";

router.get("/files", async (req, res) => {
  const data = await fs.readFile(path.join(UPLOADS, path.basename(String(req.query.name))));
  res.send(data);
});

export default router;
"""}),
    case("ts-path-prefix-check", "path_traversal", "none", {"src/routes/files.ts": EXPRESS + r"""import fs from "fs/promises";
import path from "path";

const UPLOADS = path.resolve("/srv/uploads");

router.get("/files", async (req, res) => {
  const file = path.resolve(UPLOADS, String(req.query.name));
  if (!file.startsWith(UPLOADS + path.sep)) {
    return res.status(400).end();
  }
  res.send(await fs.readFile(file));
});

export default router;
"""}),
    # ---------------------------------------------------------------- secret exposure (TS)
    case("ts-secret-hardcoded-stripe", "secret_exposure", "flagged", {"lib/billing.ts": 'import Stripe from "stripe";\n\n'
         f'export const stripe = new Stripe("{STRIPE_LIVE}", {{ apiVersion: "2024-06-20" }});\n'}),
    case("ts-secret-next-public", "secret_exposure", "flagged", {"components/Chat.tsx": r""""use client";

export function Chat() {
  const key = process.env.NEXT_PUBLIC_OPENAI_SECRET_KEY;
  return <button onClick={() => fetch("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${key}` } })}>Test</button>;
}
"""}),
    case("ts-secret-in-response", "secret_exposure", "flagged", {"app/api/debug/route.ts": NEXT + r"""
export async function GET() {
  return NextResponse.json({ token: process.env.GITHUB_APP_PRIVATE_KEY });
}
"""}),
    case("ts-secret-env-server", "secret_exposure", "none", {"lib/billing.ts": r"""import Stripe from "stripe";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: "2024-06-20" });
"""}),
    case("ts-secret-public-anon", "secret_exposure", "none", {"lib/supabase.ts": r"""import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
"""}),
    case("ts-secret-public-map-token-and-flag", "secret_exposure", "none", {"components/Map.tsx": r""""use client";

const TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;
const PRIVATE_MODE = process.env.NEXT_PUBLIC_PRIVATE_MODE_ENABLED === "true";

export function Map() {
  return <div data-token={TOKEN} data-private={PRIVATE_MODE} />;
}
"""}, note="Map tokens are designed to be public; a *_ENABLED flag is not a secret."),
    case("ts-secret-masked-log", "secret_exposure", "none", {"scripts/check-env.ts": r"""
const token = process.env.UPSTASH_VECTOR_REST_TOKEN ?? "";
console.log(`Token: ${token.slice(0, 4)}…${token.slice(-4)}`);
console.log("Key present:", !!process.env.RESEND_API_KEY);
"""}),
    case("ts-secret-options-object-result", "secret_exposure", "none", {"app/api/sidekick/act/route.ts": NEXT + r"""
async function generate(opts: { apiKey: string; model: string; prompt: string }) {
  const res = await fetch("https://generativelanguage.googleapis.com/v1beta/models", {
    method: "POST", headers: { "x-goog-api-key": opts.apiKey }, body: JSON.stringify({ prompt: opts.prompt }),
  });
  const data = await res.json();
  return { text: String(data.text), model: opts.model };
}

export async function POST(request: NextRequest) {
  const apiKey = process.env.GEMINI_API_KEY;
  const { prompt } = await request.json();
  const out = await generate({ apiKey: apiKey!, model: "gemini-2.5-flash", prompt });
  console.log(`answered model=${out.model}`);
  return NextResponse.json({ text: out.text, model: out.model });
}
"""}, note="The helper's result is model output, not the credential in its options object."),
    case("ts-secret-test-fixture", "secret_exposure", "needs_context", {"__tests__/lib/redact.test.ts":
         'import { redact } from "@/lib/redact";\n\n'
         f'it("masks keys", () => {{\n  expect(redact("{STRIPE_LIVE}")).not.toContain("live");\n}});\n'},
         note="A credential-shaped value in a test file is usually a fake fixture: verify, don't alarm."),
    # ---------------------------------------------------------------- missing authorization (TS)
    case("ts-auth-delete-unguarded", "missing_authorization", "flagged", {"app/api/projects/[id]/route.ts": NEXT + r"""import { db } from "@/lib/db";

export async function DELETE(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  await db.project.delete({ where: { id } });
  return NextResponse.json({ deleted: id });
}
"""}),
    case("ts-auth-server-action", "missing_authorization", "flagged", {"app/admin/actions.ts": r""""use server";
import { db } from "@/lib/db";

export async function setRole(userId: string, role: string) {
  await db.user.update({ where: { id: userId }, data: { role } });
}
"""}),
    case("ts-auth-guarded", "missing_authorization", "none", {"app/api/projects/[id]/route.ts": NEXT + r"""import { auth } from "@/auth";
import { db } from "@/lib/db";

export async function DELETE(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const { id } = await params;
  await db.project.delete({ where: { id, ownerId: session.user.id } });
  return NextResponse.json({ deleted: id });
}
"""}),
    case("ts-auth-webhook-signature", "missing_authorization", "none", {"app/api/stripe/webhook/route.ts": NEXT + r"""import Stripe from "stripe";
import { db } from "@/lib/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: NextRequest) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  await db.payment.create({ data: { eventId: event.id } });
  return NextResponse.json({ received: true });
}
"""}),
    case("ts-auth-configured-public", "missing_authorization", "none", {"app/api/health/route.ts": NEXT + r"""import { db } from "@/lib/db";

export async function POST() {
  await db.healthCheck.create({ data: { at: new Date() } });
  return NextResponse.json({ ok: true });
}
"""}, project={"public_routes": ["app/api/health/**"]}),
    case("ts-auth-cron-secret-variable", "missing_authorization", "none", {"app/api/cron/purge/route.ts": NEXT + r"""import { db } from "@/lib/db";

export async function POST(request: NextRequest) {
  const cronSecret = process.env.CRON_SECRET;
  const token = request.headers.get("authorization")?.replace("Bearer ", "");
  if (!cronSecret || token !== cronSecret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  await db.session.deleteMany({ where: { expired: true } });
  return NextResponse.json({ ok: true });
}
"""}),
    case("ts-auth-custom-webhook-verifier", "missing_authorization", "none", {"app/api/ai/fal-webhook/route.ts": NEXT + r"""import { verifyFalWebhook } from "@/lib/fal";
import { storage } from "@/lib/appwrite";

export async function POST(request: NextRequest) {
  const raw = await request.text();
  const verification = await verifyFalWebhook({ body: raw, headers: request.headers });
  if (!verification.ok) return NextResponse.json({ error: "bad signature" }, { status: 401 });
  await storage.createFile("renders", "unique()", raw);
  return NextResponse.json({ ok: true });
}
"""}),
    case("ts-auth-oauth-state-callback", "missing_authorization", "none", {"app/api/oauth/[service]/callback/route.ts": NEXT + r"""import { consumeNativeOAuthAttempt } from "@/lib/oauth";
import { adminDatabases } from "@/lib/appwrite";

export async function GET(request: NextRequest, { params }: { params: Promise<{ service: string }> }) {
  const { service } = await params;
  const attempt = await consumeNativeOAuthAttempt(request, service, request.nextUrl.searchParams.get("state"));
  await adminDatabases.updateDocument("db", "credentials", attempt.credentialId, { connected: true });
  return NextResponse.redirect(new URL("/settings", request.url));
}
"""}),
    case("ts-auth-rate-limited-public-form", "missing_authorization", "needs_context", {"app/api/bio/[slug]/lead/route.ts": NEXT + r"""import { rateLimit } from "@/lib/rateLimit";
import { adminDatabases } from "@/lib/appwrite";

export async function POST(request: NextRequest) {
  const limited = await rateLimit(request);
  if (limited) return limited;
  const { email } = await request.json();
  await adminDatabases.createDocument("db", "leads", "unique()", { email });
  return NextResponse.json({ ok: true });
}
"""}, note="Rate limiting an anonymous write signals a public endpoint: ask, don't flag high."),
    # ---------------------------------------------------------------- insecure auth/crypto (TS)
    case("ts-crypto-math-random-token", "insecure_auth_crypto", "flagged", {"lib/reset.ts": r"""import { db } from "@/lib/db";

export async function createResetToken(userId: string) {
  const resetToken = Math.random().toString(36).slice(2);
  await db.passwordReset.create({ data: { userId, resetToken } });
  return resetToken;
}
"""}),
    case("ts-crypto-jwt-decode-auth", "insecure_auth_crypto", "needs_context", {"lib/session.ts": r"""import jwt from "jsonwebtoken";

export function currentUserId(token: string) {
  const claims = jwt.decode(token) as { sub?: string } | null;
  return claims?.sub;
}
"""}),
    case("ts-crypto-md5-password", "insecure_auth_crypto", "flagged", {"lib/passwords.ts": r"""import crypto from "crypto";

export function hashPassword(password: string) {
  return crypto.createHash("md5").update(password).digest("hex");
}
"""}),
    case("ts-crypto-random-bytes", "insecure_auth_crypto", "none", {"lib/reset.ts": r"""import crypto from "crypto";
import { db } from "@/lib/db";

export async function createResetToken(userId: string) {
  const resetToken = crypto.randomBytes(32).toString("hex");
  await db.passwordReset.create({ data: { userId, resetToken } });
  return resetToken;
}
"""}),
    case("ts-crypto-jwt-verify", "insecure_auth_crypto", "none", {"lib/session.ts": r"""import jwt from "jsonwebtoken";

export function currentUserId(token: string) {
  const claims = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ["HS256"] }) as { sub?: string };
  return claims.sub;
}
"""}),
    case("ts-crypto-bcrypt", "insecure_auth_crypto", "none", {"lib/passwords.ts": r"""import bcrypt from "bcryptjs";

export async function hashPassword(password: string) {
  return bcrypt.hash(password, 12);
}
"""}),
    case("ts-crypto-pwned-passwords-sha1", "insecure_auth_crypto", "none", {"app/api/password-check/route.ts": NEXT + r"""import crypto from "crypto";

export async function POST(request: NextRequest) {
  const { password } = await request.json();
  const sha1Hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const res = await fetch(`https://api.pwnedpasswords.com/range/${sha1Hash.slice(0, 5)}`);
  const breached = (await res.text()).includes(sha1Hash.slice(5));
  return NextResponse.json({ breached });
}
"""}, note="Have I Been Pwned's k-anonymity API requires SHA-1; this is not password storage."),
    # ---------------------------------------------------------------- unsafe configuration (TS)
    case("ts-config-tls-disabled", "unsafe_security_configuration", "flagged", {"lib/http.ts": r"""import https from "https";

export const agent = new https.Agent({ rejectUnauthorized: false });
"""}),
    case("ts-config-cors-wildcard-credentials", "unsafe_security_configuration", "flagged", {"src/server.ts": r"""import express from "express";
import cors from "cors";

const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.listen(3000);
"""}),
    case("ts-config-cookie-not-httponly", "unsafe_security_configuration", "flagged", {"app/api/login/route.ts": NEXT + r"""import { cookies } from "next/headers";
import { createSession } from "@/lib/session";

export async function POST(request: NextRequest) {
  const { email, password } = await request.json();
  const token = await createSession(email, password);
  (await cookies()).set("session", token, { httpOnly: false, path: "/" });
  return NextResponse.json({ ok: true });
}
"""}),
    case("ts-config-tls-custom-ca", "unsafe_security_configuration", "none", {"lib/http.ts": r"""import fs from "fs";
import https from "https";

export const agent = new https.Agent({ ca: fs.readFileSync(process.env.INTERNAL_CA_PATH!) });
"""}),
    case("ts-config-cors-allowlist", "unsafe_security_configuration", "none", {"src/server.ts": r"""import express from "express";
import cors from "cors";

const app = express();
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
app.listen(3000);
"""}),
    case("ts-config-cookie-secure", "unsafe_security_configuration", "none", {"app/api/login/route.ts": NEXT + r"""import { cookies } from "next/headers";
import { createSession } from "@/lib/session";

export async function POST(request: NextRequest) {
  const { email, password } = await request.json();
  const token = await createSession(email, password);
  (await cookies()).set("session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
  return NextResponse.json({ ok: true });
}
"""}),
    # ---------------------------------------------------------------- Python web checks
    case("py-ssrf-requests", "ssrf", "flagged", {"app/proxy.py": r"""import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/proxy")
def proxy():
    return requests.get(request.args["url"], timeout=5).text
"""}, language="python"),
    case("py-ssrf-fixed-host", "ssrf", "none", {"app/proxy.py": r"""import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/items")
def item():
    item_id = int(request.args["id"])
    return requests.get(f"https://api.example.com/items/{item_id}", timeout=5).text
"""}, language="python"),
    case("py-ssrf-fastapi-httpx-client", "ssrf", "flagged", {"app/main.py": r"""import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/fetch")
async def fetch(url: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
    return {"status": response.status_code}
"""}, language="python", note="Moved from the held-out split (ho-py-ssrf-fastapi-httpx) after the fix."),
    case("py-ssrf-requests-session-module", "ssrf", "flagged", {"app/webhooks.py": r"""import requests
from flask import Flask, request

app = Flask(__name__)
session = requests.Session()


@app.post("/webhooks/test")
def test_webhook():
    response = session.post(request.json["target"], json={"ping": True}, timeout=5)
    return {"status": response.status_code}
"""}, language="python"),
    case("py-ssrf-httpx-client-relative-path", "ssrf", "none", {"app/main.py": r"""import httpx
from fastapi import FastAPI

app = FastAPI()
API = "https://api.example.com"


@app.get("/items/{item_id}")
async def item(item_id: int):
    async with httpx.AsyncClient(base_url=API) as client:
        response = await client.get(f"/items/{item_id}")
    return response.json()
"""}, language="python"),
    case("py-redirect-next", "open_redirect", "flagged", {"app/auth.py": r"""from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/login/done")
def login_done():
    return redirect(request.args.get("next", "/"))
"""}, language="python"),
    case("py-redirect-fixed", "open_redirect", "none", {"app/auth.py": r"""from flask import Flask, redirect, url_for

app = Flask(__name__)


@app.get("/logout")
def logout():
    return redirect(url_for("login"))
"""}, language="python"),
    case("py-xss-markup", "xss", "flagged", {"app/views.py": r"""from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.get("/hello")
def hello():
    return Markup("<h1>Hello " + request.args["name"] + "</h1>")
"""}, language="python"),
    case("py-xss-template", "xss", "none", {"app/views.py": r"""from flask import Flask, render_template, request

app = Flask(__name__)


@app.get("/hello")
def hello():
    return render_template("hello.html", name=request.args["name"])
"""}, language="python"),
    case("py-path-join", "path_traversal", "flagged", {"app/files.py": r"""import os
from flask import Flask, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.get("/files")
def download():
    with open(os.path.join(UPLOADS, request.args["name"]), "rb") as handle:
        return handle.read()
"""}, language="python"),
    case("py-path-send-from-directory", "path_traversal", "none", {"app/files.py": r"""from flask import Flask, request, send_from_directory

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.get("/files")
def download():
    return send_from_directory(UPLOADS, request.args["name"])
"""}, language="python"),
    case("py-path-pathlib-read-text", "path_traversal", "flagged", {"app/docs.py": r"""from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
DOCS = Path("/srv/docs")


@app.get("/docs")
def doc():
    return (DOCS / request.args["name"]).read_text()
"""}, language="python", note="Moved from the held-out split (ho-py-path-pathlib) after the fix."),
    case("py-path-pathlib-lexical-check", "path_traversal", "flagged", {"app/docs.py": r"""from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
DOCS = Path("/srv/docs")


@app.get("/docs")
def doc():
    target = DOCS / request.args["name"]
    if not target.is_relative_to(DOCS):
        abort(404)
    return target.read_text()
"""}, language="python", note="is_relative_to on an unresolved path is lexical: docs/../../etc/passwd passes it."),
    case("py-path-pathlib-resolved-contained", "path_traversal", "none", {"app/docs.py": r"""from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
DOCS = Path("/srv/docs").resolve()


@app.get("/docs")
def doc():
    target = (DOCS / request.args["name"]).resolve()
    if not target.is_relative_to(DOCS):
        abort(404)
    return target.read_text()
"""}, language="python"),
    case("py-path-realpath-prefix-check", "path_traversal", "none", {"app/files.py": r"""import os

from flask import Flask, abort, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.get("/files")
def download():
    path = os.path.realpath(os.path.join(UPLOADS, request.args["name"]))
    if not path.startswith(UPLOADS + os.sep):
        abort(404)
    with open(path, "rb") as handle:
        return handle.read()
"""}, language="python"),
    case("py-path-secure-filename", "path_traversal", "none", {"app/files.py": r"""import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.get("/files")
def download():
    with open(os.path.join(UPLOADS, secure_filename(request.args["name"])), "rb") as handle:
        return handle.read()
"""}, language="python"),
    case("py-sql-allowlist-positive-return", "sql_injection", "none", {"app/reports.py": r"""import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("reports.db", check_same_thread=False)
ALLOWED_COLUMNS = {"name", "created_at"}


@app.get("/report")
def report():
    column = request.args["sort"]
    if column in ALLOWED_COLUMNS:
        return db.execute(f"SELECT * FROM report ORDER BY {column}").fetchall()
    return db.execute("SELECT * FROM report").fetchall()
"""}, language="python"),
    case("py-sql-allowlist-fallthrough", "sql_injection", "flagged", {"app/reports.py": r"""import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("reports.db", check_same_thread=False)
ALLOWED_COLUMNS = {"name", "created_at"}


@app.get("/report")
def report():
    column = request.args["sort"]
    if column in ALLOWED_COLUMNS:
        return db.execute(f"SELECT * FROM report ORDER BY {column}").fetchall()
    return db.execute(f"SELECT * FROM report ORDER BY {column} DESC").fetchall()
"""}, language="python", line=15, note="After a positive check whose body returns, the rest runs only when it failed."),
    case("py-code-eval", "code_injection", "flagged", {"app/calc.py": r"""from flask import Flask, request

app = Flask(__name__)


@app.post("/calc")
def calc():
    return {"result": eval(request.form["expression"])}
"""}, language="python"),
    case("py-code-literal-eval", "code_injection", "none", {"app/calc.py": r"""import ast
from flask import Flask, request

app = Flask(__name__)


@app.post("/calc")
def calc():
    return {"result": ast.literal_eval(request.form["expression"])}
"""}, language="python"),
    case("py-secret-hardcoded-aws", "secret_exposure", "flagged", {"app/storage.py": "import boto3\n\n"
         f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"\nclient = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)\n'},
         language="python"),
    case("py-secret-from-environment", "secret_exposure", "none", {"app/storage.py": r"""import os

import boto3

client = boto3.client("s3", aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"])
"""}, language="python"),
    case("py-auth-unguarded-delete", "missing_authorization", "flagged", {"app/api.py": r"""from flask import Flask

from app.models import Project, db

app = Flask(__name__)


@app.post("/projects/<int:project_id>/delete")
def delete_project(project_id):
    db.session.delete(Project.query.get_or_404(project_id))
    db.session.commit()
    return {"deleted": project_id}
"""}, language="python"),
    case("py-auth-login-required", "missing_authorization", "none", {"app/api.py": r"""from flask import Flask
from flask_login import login_required

from app.models import Project, db

app = Flask(__name__)


@app.post("/projects/<int:project_id>/delete")
@login_required
def delete_project(project_id):
    db.session.delete(Project.query.get_or_404(project_id))
    db.session.commit()
    return {"deleted": project_id}
"""}, language="python"),
    case("py-crypto-weak-random-token", "insecure_auth_crypto", "flagged", {"app/tokens.py": r"""import random


def make_reset_token():
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return reset_token
"""}, language="python"),
    case("py-crypto-secrets-token", "insecure_auth_crypto", "none", {"app/tokens.py": r"""import secrets


def make_reset_token():
    reset_token = secrets.token_hex(16)
    return reset_token
"""}, language="python"),
    case("py-config-verify-false", "unsafe_security_configuration", "flagged", {"app/client.py": r"""import requests


def fetch_status():
    return requests.get("https://internal.example.com/status", verify=False, timeout=5).json()
"""}, language="python"),
    case("py-config-verify-default", "unsafe_security_configuration", "none", {"app/client.py": r"""import requests


def fetch_status():
    return requests.get("https://internal.example.com/status", timeout=5).json()
"""}, language="python"),
    # ---------------------------------------------------------------- Rust / Tauri
    case("rs-cmd-tauri-sh", "command_injection", "flagged", {"src-tauri/src/commands.rs": r"""use std::process::Command;

#[tauri::command]
pub fn run_script(script: String) -> Result<String, String> {
    let output = Command::new("sh").arg("-c").arg(script).output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
"""}, language="rust"),
    case("rs-cmd-option-injection", "command_injection", "flagged", {"src-tauri/src/commands.rs": r"""use std::process::Command;

#[tauri::command]
pub fn clone_repo(url: String) -> Result<(), String> {
    Command::new("git").arg("clone").arg(&url).status().map_err(|e| e.to_string())?;
    Ok(())
}
"""}, language="rust"),
    case("rs-cmd-axum-query-destructured", "command_injection", "flagged", {"src/handlers.rs": r"""use axum::extract::Query;
use std::collections::HashMap;
use std::process::Command;

pub async fn run(Query(params): Query<HashMap<String, String>>) -> String {
    let output = Command::new("sh").arg("-c").arg(&params["cmd"]).output().unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}
"""}, language="rust", note="Moved from the held-out split (ho-rs-cmd-axum-query) after the fix."),
    case("rs-cmd-axum-query-unused", "command_injection", "none", {"src/handlers.rs": r"""use axum::extract::Query;
use std::collections::HashMap;
use std::process::Command;

pub async fn status(Query(params): Query<HashMap<String, String>>) -> String {
    let output = Command::new("git").arg("status").arg("--short").output().unwrap();
    format!("{}: {}", params["label"], String::from_utf8_lossy(&output.stdout))
}
"""}, language="rust"),
    case("rs-path-axum-path-destructured", "path_traversal", "flagged", {"src/handlers.rs": r"""use axum::extract::Path;

pub async fn read_note(Path(name): Path<String>) -> Result<String, String> {
    std::fs::read_to_string(format!("/srv/notes/{}", name)).map_err(|e| e.to_string())
}
"""}, language="rust"),
    case("rs-cmd-fixed", "command_injection", "none", {"src-tauri/src/commands.rs": r"""use std::process::Command;

#[tauri::command]
pub fn git_status() -> Result<String, String> {
    let output = Command::new("git").arg("status").arg("--short").output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
"""}, language="rust"),
    case("rs-sql-format", "sql_injection", "flagged", {"src-tauri/src/db.rs": r"""use sqlx::SqlitePool;

#[tauri::command]
pub async fn find_user(pool: tauri::State<'_, SqlitePool>, name: String) -> Result<usize, String> {
    let rows = sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_all(pool.inner()).await.map_err(|e| e.to_string())?;
    Ok(rows.len())
}
"""}, language="rust"),
    case("rs-sql-bind", "sql_injection", "none", {"src-tauri/src/db.rs": r"""use sqlx::SqlitePool;

#[tauri::command]
pub async fn find_user(pool: tauri::State<'_, SqlitePool>, name: String) -> Result<usize, String> {
    let rows = sqlx::query("SELECT * FROM users WHERE name = ?").bind(&name)
        .fetch_all(pool.inner()).await.map_err(|e| e.to_string())?;
    Ok(rows.len())
}
"""}, language="rust"),
    case("rs-path-format", "path_traversal", "flagged", {"src-tauri/src/notes.rs": r"""#[tauri::command]
pub fn read_note(name: String) -> Result<String, String> {
    std::fs::read_to_string(format!("/srv/notes/{}", name)).map_err(|e| e.to_string())
}
"""}, language="rust"),
    case("rs-path-fixed", "path_traversal", "none", {"src-tauri/src/notes.rs": r"""#[tauri::command]
pub fn read_settings() -> Result<String, String> {
    std::fs::read_to_string("/srv/app/settings.json").map_err(|e| e.to_string())
}
"""}, language="rust"),
    case("rs-path-helper-std-path", "path_traversal", "none", {"src-tauri/src/fsx.rs": r"""use std::path::Path;

pub fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}
"""}, language="rust", note="A std::path::Path parameter of an internal helper is not an axum Path<_> extractor."),
    case("rs-ssrf-reqwest", "ssrf", "flagged", {"src-tauri/src/net.rs": r"""#[tauri::command]
pub async fn fetch_url(url: String) -> Result<String, String> {
    let body = reqwest::get(&url).await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?;
    Ok(body)
}
"""}, language="rust"),
    case("rs-ssrf-fixed", "ssrf", "none", {"src-tauri/src/net.rs": r"""#[tauri::command]
pub async fn fetch_status() -> Result<String, String> {
    let body = reqwest::get("https://status.example.com/api/v2/status.json").await.map_err(|e| e.to_string())?
        .text().await.map_err(|e| e.to_string())?;
    Ok(body)
}
"""}, language="rust"),
    case("rs-tls-disabled", "unsafe_security_configuration", "flagged", {"src-tauri/src/net.rs": r"""pub fn client() -> reqwest::Client {
    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()
}
"""}, language="rust"),
    case("rs-secret-hardcoded", "secret_exposure", "flagged", {"src-tauri/src/billing.rs":
         f'const STRIPE_KEY: &str = "{STRIPE_LIVE}";\n\npub fn key() -> &\'static str {{\n    STRIPE_KEY\n}}\n'},
         language="rust"),
    # ---------------------------------------------------------------- GitHub Actions: expression injection
    case("gha-inject-prt-title-run", "workflow_injection", "flagged", {".github/workflows/greet.yml": r"""on: pull_request_target
permissions:
  pull-requests: write
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Thanks for the pull request!"
          echo "Title: ${{ github.event.pull_request.title }}"
"""}, language="github_actions", line=10),
    case("gha-inject-issue-comment-github-script", "workflow_injection", "flagged", {".github/workflows/react.yml": r"""on:
  issue_comment:
    types: [created]
permissions:
  issues: write
jobs:
  react:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            const body = `${{ github.event.comment.body }}`;
            if (body.includes("+1")) core.info("thumbs up");
"""}, language="github_actions", line=13),
    case("gha-inject-tojson-event", "workflow_injection", "flagged", {".github/workflows/debug.yml": r"""on: [issue_comment]
permissions: {}
jobs:
  dump:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event) }}' | jq .comment.id
"""}, language="github_actions", line=7, note="toJSON output contains the comment body; its quotes end the shell string."),
    case("gha-inject-format-function", "workflow_injection", "flagged", {".github/workflows/notify.yml": r"""on:
  issues:
    types: [opened]
permissions: {}
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ./notify.sh "${{ format('New issue: {0}', github.event.issue.title) }}"
"""}, language="github_actions", line=10),
    case("gha-inject-index-syntax", "workflow_injection", "flagged", {".github/workflows/title.yml": r"""on: pull_request_target
permissions: {}
jobs:
  title:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event['pull_request']['title'] }}"
"""}, language="github_actions", line=7),
    case("gha-inject-push-commits-join", "workflow_injection", "flagged", {".github/workflows/changelog.yml": r"""on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  changelog:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ join(github.event.commits.*.message, ', ') }}" >> CHANGELOG.txt
"""}, language="github_actions", line=10),
    case("gha-inject-pull-request-head-ref", "workflow_injection", "flagged", {".github/workflows/branch.yml": r"""on: pull_request
permissions:
  contents: read
jobs:
  branch:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Testing ${{ github.head_ref }}"
"""}, language="github_actions", line=8, note="Medium: fork pull requests get a read-only token here."),
    case("gha-inject-workflow-call", "workflow_injection", "flagged", {".github/workflows/reusable-label.yml": r"""on:
  workflow_call:
permissions: {}
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Labeling ${{ github.event.issue.title }}"
"""}, language="github_actions", line=8, note="The caller's event is unknown, so any untrusted field may be present."),
    case("gha-inject-multiline-expression", "workflow_injection", "flagged", {".github/workflows/multi.yml": r"""on:
  discussion:
    types: [created]
permissions: {}
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -e
          echo "${{
            github.event.discussion.title
          }}"
"""}, language="github_actions", line=11),
    case("gha-inject-quoted-on-key-flow-style", "workflow_injection", "flagged", {".github/workflows/flow.yml": r""""on": {issues: {types: [opened]}}
permissions: {}
jobs:
  flow:
    runs-on: ubuntu-latest
    steps: [{run: "echo ${{ github.event.issue.body }}"}]
"""}, language="github_actions", line=6, note="Quoted on: key and flow-style YAML."),
    case("gha-inject-env-indirection-safe", "workflow_injection", "none", {".github/workflows/safe-title.yml": r"""on: pull_request_target
permissions: {}
jobs:
  title:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
          HEAD: ${{ github.head_ref }}
        run: |
          echo "Title: $TITLE"
          printf '%s\n' "$HEAD"
"""}, language="github_actions"),
    case("gha-inject-safe-fields", "workflow_injection", "none", {".github/workflows/meta.yml": r"""on: [pull_request_target, issues]
permissions: {}
jobs:
  meta:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.pull_request.number }} ${{ github.event.pull_request.head.sha }}"
          echo "${{ github.actor }} ${{ github.event.issue.user.login }} ${{ github.event.issue.number }}"
          echo "${{ github.repository }} ${{ github.run_id }} ${{ github.sha }}"
"""}, language="github_actions"),
    case("gha-inject-trigger-does-not-supply", "workflow_injection", "none", {".github/workflows/push-only.yml": r"""on:
  push:
    branches: [main]
permissions: {}
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }} ${{ github.event.pull_request.title }}"
"""}, language="github_actions", note="Push events carry no issue or pull request: the expressions are empty."),
    case("gha-inject-condition-name-and-inputs", "workflow_injection", "none", {".github/workflows/conditions.yml": r"""on:
  issue_comment:
    types: [created]
permissions: {}
jobs:
  check:
    if: contains(github.event.comment.body, '/ok')
    runs-on: ubuntu-latest
    steps:
      - name: Comment ${{ github.event.comment.body }}
        uses: peter-evans/create-or-update-comment@71345be0265236311c031f5c7866368bd1eff043 # v4.0.0
        with:
          body: ${{ github.event.comment.body }}
      - run: echo "${{ github.event.comment.body == '/ok' }}"
"""}, language="github_actions", note="if:, step names, ordinary action inputs and boolean results are not scripts."),
    case("gha-inject-tojson-quoted-heredoc-data", "workflow_injection", "none", {".github/workflows/context.yml": r"""on: [pull_request_target, push]
permissions: {}
jobs:
  context:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat > "${RUNNER_TEMP}/github_context.json" << '__GITHUB_CONTEXT_END__'
          ${{ toJson(github) }}
          __GITHUB_CONTEXT_END__
          cat <<'EOF' > title.txt
          ${{ github.event.pull_request.title }}
          EOF
"""}, language="github_actions",
         note="From the Airflow triage: a quoted heredoc expands nothing, and toJSON output or a title has no newline "
              "that could end it early."),
    case("gha-inject-body-quoted-heredoc", "workflow_injection", "flagged", {".github/workflows/body.yml": r"""on: issues
permissions: {}
jobs:
  save:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF' > body.md
          ${{ github.event.issue.body }}
          EOF
"""}, language="github_actions", line=9, note="An issue body can contain a line that ends the heredoc early."),
    case("gha-inject-title-unquoted-heredoc", "workflow_injection", "flagged", {".github/workflows/unquoted.yml": r"""on: issues
permissions: {}
jobs:
  save:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF > title.txt
          ${{ github.event.issue.title }}
          EOF
"""}, language="github_actions", line=9, note="An unquoted heredoc runs $(...) in the title."),
    case("gha-inject-quoted-heredoc-into-bash", "workflow_injection", "flagged", {".github/workflows/heredoc-script.yml": r"""on: issues
permissions: {}
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: |
          bash <<'EOF'
          echo "${{ github.event.issue.title }}"
          EOF
"""}, language="github_actions", line=9, note="The heredoc is the script bash runs."),
    case("gha-inject-event-name-gate", "workflow_injection", "none", {".github/workflows/mixed.yml": r"""on: [push, issues]
permissions: {}
jobs:
  release:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""}, language="github_actions", note="The job runs only for push, which supplies no issue."),
    # ---------------------------------------------------------------- GitHub Actions: untrusted checkout
    case("gha-checkout-prt-head-ref-make", "untrusted_checkout", "flagged", {".github/workflows/bench.yml": f"""on: pull_request_target
permissions:
  contents: read
jobs:
  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: ${{{{ github.event.pull_request.head.ref }}}}
          repository: ${{{{ github.event.pull_request.head.repo.full_name }}}}
      - run: make bench
"""}, language="github_actions", line=10),
    case("gha-checkout-prt-refs-pull-merge", "untrusted_checkout", "flagged", {".github/workflows/merge-check.yml": f"""on: pull_request_target
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: refs/pull/${{{{ github.event.number }}}}/merge
"""}, language="github_actions", line=10, note="High: checked out but nothing visibly runs from it."),
    case("gha-checkout-prt-git-fetch-checkout", "untrusted_checkout", "flagged", {".github/workflows/fetch.yml": f"""on: pull_request_target
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - env:
          PR: ${{{{ github.event.pull_request.number }}}}
        run: |
          git fetch origin "pull/$PR/head:pr-$PR"
          git checkout "pr-$PR"
          npm test
"""}, language="github_actions", line=13),
    case("gha-checkout-prt-env-sha", "untrusted_checkout", "flagged", {".github/workflows/env-sha.yml": f"""on: pull_request_target
permissions:
  contents: read
env:
  HEAD_SHA: ${{{{ github.event.pull_request.head.sha }}}}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: ${{{{ env.HEAD_SHA }}}}
      - run: ./gradlew build
"""}, language="github_actions", line=12),
    case("gha-checkout-local-action", "untrusted_checkout", "flagged", {".github/workflows/local.yml": f"""on: pull_request_target
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - uses: ./.github/actions/lint
"""}, language="github_actions", line=10),
    case("gha-checkout-label-gated", "untrusted_checkout", "flagged", {".github/workflows/labeled.yml": f"""on:
  pull_request_target:
    types: [labeled]
permissions:
  contents: read
jobs:
  e2e:
    if: contains(github.event.pull_request.labels.*.name, 'safe to test')
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: npm ci && npm run e2e
"""}, language="github_actions", line=13, note="A label gate lowers the severity to high; it is still reported."),
    case("gha-checkout-workflow-run-artifact-exec", "untrusted_checkout", "flagged", {".github/workflows/post-results.yml": r"""on:
  workflow_run:
    workflows: [Tests]
    types: [completed]
permissions:
  pull-requests: write
jobs:
  post:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with:
          name: results
          path: results
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: bash ./results/post-comment.sh
"""}, language="github_actions", line=17),
    case("gha-checkout-prt-fetch-only", "untrusted_checkout", "none", {".github/workflows/review.yml": f"""on: pull_request_target
permissions: {{}}
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - env:
          PR: ${{{{ github.event.pull_request.number }}}}
        run: |
          git fetch --no-tags origin "+refs/pull/$PR/head:refs/remotes/review/head"
          git diff --stat HEAD refs/remotes/review/head
          python3 tools/review.py --base HEAD --head refs/remotes/review/head
"""}, language="github_actions", note="The change is fetched as data only; nothing from it is checked out or run."),
    case("gha-checkout-workflow-run-artifact-data", "untrusted_checkout", "none", {".github/workflows/sarif-upload.yml": r"""on:
  workflow_run:
    workflows: [Scan]
    types: [completed]
permissions:
  security-events: write
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with:
          name: sarif
          path: sarif
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: jq -e '.runs | length > 0' sarif/results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sarif/results.sarif
"""}, language="github_actions", note="Artifacts read as data (the SARIF hub's recommended pattern)."),
    case("gha-checkout-association-guard", "untrusted_checkout", "none", {".github/workflows/maintainer-test.yml": f"""on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  test:
    if: >-
      github.event.issue.pull_request && startsWith(github.event.comment.body, '/test')
      && contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: refs/pull/${{{{ github.event.issue.number }}}}/head
      - run: make test
"""}, language="github_actions"),
    case("gha-checkout-workflow-run-push-gate", "untrusted_checkout", "none", {".github/workflows/deploy-after-ci.yml": f"""on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: read
jobs:
  deploy:
    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
        with:
          ref: ${{{{ github.event.workflow_run.head_sha }}}}
      - run: make deploy
"""}, language="github_actions"),
    # ---------------------------------------------------------------- GitHub Actions: privileges
    case("gha-perms-write-all-push", "excessive_privileges", "flagged", {".github/workflows/build.yml": f"""on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - run: make
"""}, language="github_actions", line=2),
    case("gha-perms-broad-write-issue-comment", "excessive_privileges", "flagged", {".github/workflows/bot.yml": r"""on:
  issue_comment:
    types: [created]
jobs:
  bot:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      contents: write
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: core.info(String(context.payload.comment.id))
"""}, language="github_actions", line=9),
    case("gha-perms-default-prt", "excessive_privileges", "flagged", {".github/workflows/labels.yml": r"""on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9 # v5.0.0
"""}, language="github_actions", line=2),
    case("gha-perms-read-all", "excessive_privileges", "none", {".github/workflows/lint.yml": f"""on: [pull_request_target]
permissions: read-all
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - run: make lint
"""}, language="github_actions"),
    case("gha-perms-contents-write-push", "excessive_privileges", "none", {".github/workflows/tag.yml": f"""on:
  push:
    branches: [main]
permissions:
  contents: write
jobs:
  tag:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - run: git tag "v$(cat VERSION)" && git push --tags
"""}, language="github_actions", note="A write token on a trusted trigger is the intended use."),
    case("gha-perms-merged-guard", "excessive_privileges", "none", {".github/workflows/release-on-merge.yml": f"""on:
  pull_request_target:
    types: [closed]
permissions:
  contents: write
jobs:
  release:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - run: ./scripts/release.sh
"""}, language="github_actions"),
    # ---------------------------------------------------------------- GitHub Actions: unpinned dependencies
    case("gha-unpinned-branch", "unpinned_dependency", "flagged", {".github/workflows/deploy.yml": f"""on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHECKOUT}
      - uses: example-org/deploy-action@main
"""}, language="github_actions", line=9),
    case("gha-unpinned-docker-uses", "unpinned_dependency", "flagged", {".github/workflows/docker-step.yml": r"""on: push
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.20
        with:
          args: echo hello
"""}, language="github_actions", line=7),
    case("gha-unpinned-job-container", "unpinned_dependency", "flagged", {".github/workflows/container.yml": r"""on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20-bookworm
    steps:
      - run: node --version
"""}, language="github_actions", line=7),
    case("gha-unpinned-reusable-workflow", "unpinned_dependency", "flagged", {".github/workflows/call.yml": r"""on: push
permissions:
  contents: read
jobs:
  shared:
    uses: example-org/shared-workflows/.github/workflows/ci.yml@v2
"""}, language="github_actions", line=6),
    case("gha-unpinned-digest-and-local", "unpinned_dependency", "none", {".github/workflows/pinned.yml": r"""on: push
permissions:
  contents: read
jobs:
  local:
    uses: ./.github/workflows/reusable.yml
  scan:
    runs-on: ubuntu-latest
    container:
      image: node:20-bookworm@sha256:a5e0ed56f2c20b9689e0f7dd498cac7e08de2a3ec2a7b2c55b3d3e4d2b4a6f81
    steps:
      - uses: docker://alpine@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d
      - uses: ./.github/actions/setup
"""}, language="github_actions"),
    # ---------------------------------------------------------------- GitHub Actions: downloads
    case("gha-download-curl-sh-https", "unverified_download", "flagged", {".github/workflows/rust.yml": r"""on: push
permissions: {}
jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
          cargo --version
"""}, language="github_actions", line=8),
    case("gha-download-bash-process-substitution", "unverified_download", "flagged", {".github/workflows/nvm.yml": r"""on: push
permissions: {}
jobs:
  node:
    runs-on: ubuntu-latest
    steps:
      - run: bash <(curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh)
"""}, language="github_actions", line=7),
    case("gha-download-pwsh-iex", "unverified_download", "flagged", {".github/workflows/windows.yml": r"""on: push
permissions: {}
jobs:
  windows:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: iwr https://get.example.dev/install.ps1 -UseBasicParsing | iex
"""}, language="github_actions", line=8),
    case("gha-download-localhost", "unverified_download", "none", {".github/workflows/e2e-local.yml": r"""on: push
permissions: {}
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - run: |
          python3 -m http.server 8080 --directory fixtures &
          curl -s http://localhost:8080/setup.sh | sh
"""}, language="github_actions", note="A loopback test server is not a supply-chain download."),
    case("gha-download-pipe-to-python-c", "unverified_download", "none", {".github/workflows/version.yml": r"""on: push
permissions: {}
jobs:
  version:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://pypi.org/pypi/requests/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])'
"""}, language="github_actions", note="python -c reads the download as data, not code."),
    # ---------------------------------------------------------------- GitHub Actions: secrets
    case("gha-secret-hardcoded-token", "secret_exposure", "flagged", {".github/workflows/release-notes.yml": f"""on: workflow_dispatch
permissions: {{}}
jobs:
  notes:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: {GITHUB_PAT}
    steps:
      - run: gh release list
"""}, language="github_actions", line=7),
    case("gha-secret-echo-direct", "secret_exposure", "flagged", {".github/workflows/echo-secret.yml": r"""on: workflow_dispatch
permissions: {}
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo "API key is ${{ secrets.API_KEY }}"
"""}, language="github_actions", line=7, note="Low: GitHub masks exact secret values in logs."),
    case("gha-secret-group-redirect", "secret_exposure", "none", {".github/workflows/outputs.yml": r"""on: workflow_dispatch
permissions: {}
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          {
            echo "token=$TOKEN"
            echo "region=us-east-1"
          } >> "$GITHUB_ENV"
"""}, language="github_actions"),
    case("gha-secret-used-not-printed", "secret_exposure", "none", {".github/workflows/api.yml": r"""on: workflow_dispatch
permissions: {}
jobs:
  call:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          curl -fsS -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/ping > /dev/null
          echo "ping ok"
"""}, language="github_actions"),
    # ---------------------------------------------------------------- Dockerfiles: downloads
    case("docker-pipe-sh-https", "unverified_download", "flagged", {"Dockerfile": r"""FROM ubuntu:24.04
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://get.docker.com | sh
USER 1000
"""}, language="dockerfile", line=3),
    case("docker-pipe-bash-http-sudo", "unverified_download", "flagged", {"docker/ci.Dockerfile": r"""FROM ubuntu:24.04
RUN wget -O - http://repo.example.org/setup.sh | sudo bash
USER 1000
"""}, language="dockerfile", line=2),
    case("docker-sh-c-substitution", "unverified_download", "flagged", {"Dockerfile": r"""FROM alpine:3.20
RUN apk add --no-cache curl zsh \
 && sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
USER 65534
"""}, language="dockerfile", line=3),
    case("docker-exec-form-sh-c", "unverified_download", "flagged", {"Dockerfile": r"""FROM alpine:3.20
RUN ["/bin/sh", "-c", "wget -qO- https://get.example.dev/install.sh | sh"]
USER 65534
"""}, language="dockerfile", line=2),
    case("docker-onbuild-run", "unverified_download", "flagged", {"base/Dockerfile": r"""FROM node:20-alpine
ONBUILD RUN curl -fsSL https://get.example.dev/hooks.sh | sh
USER node
"""}, language="dockerfile", line=2),
    case("docker-pipe-to-tar", "unverified_download", "none", {"Dockerfile": r"""FROM alpine:3.20
RUN wget -qO- https://github.com/example/tool/releases/download/v1.0.0/tool.tar.gz | tar -xz -C /usr/local/bin
USER 65534
"""}, language="dockerfile", note="An archive extracted by tar is not executed as a script."),
    case("docker-heredoc-data", "unverified_download", "none", {"Dockerfile": r"""# syntax=docker/dockerfile:1.7
FROM alpine:3.20
RUN cat <<EOF > /usr/share/doc/install.txt
Install with: curl -fsSL https://get.example.dev | sh
EOF
USER 65534
"""}, language="dockerfile", note="The heredoc is written to a file, not run."),
    case("docker-add-http", "unverified_download", "flagged", {"Dockerfile": r"""FROM debian:bookworm-slim
ADD http://downloads.example.org/agent.deb /tmp/agent.deb
RUN dpkg -i /tmp/agent.deb
USER 1000
"""}, language="dockerfile", line=2),
    case("docker-add-git-and-local", "unverified_download", "none", {"Dockerfile": r"""FROM alpine:3.20
ADD https://github.com/moby/buildkit.git#v0.14.1 /src/buildkit
ADD app.tar.gz /app/
USER 65534
"""}, language="dockerfile", note="Git sources and local archives are not remote file downloads."),
    # ---------------------------------------------------------------- Dockerfiles: secrets
    case("docker-env-aws-key", "secret_exposure", "flagged", {"Dockerfile": f"""FROM python:3.12-slim
ENV AWS_ACCESS_KEY_ID={AWS_KEY_ID}
USER 1000
"""}, language="dockerfile", line=2),
    case("docker-arg-token-builder-stage", "secret_exposure", "flagged", {"Dockerfile": r"""FROM golang:1.23 AS build
ARG GITHUB_TOKEN
RUN git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/" \
 && go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
"""}, language="dockerfile", line=2, note="Low: a builder stage's history doesn't ship, but its cache keeps the value."),
    case("docker-env-from-arg-final", "secret_exposure", "flagged", {"Dockerfile": r"""FROM node:20-alpine
ARG NPM_TOKEN
ENV NODE_AUTH_TOKEN=${NPM_TOKEN}
RUN npm ci
USER node
"""}, language="dockerfile", line=3),
    case("docker-env-secret-file-and-placeholder", "secret_exposure", "none", {"Dockerfile": r"""FROM postgres:16
ENV POSTGRES_PASSWORD_FILE=/run/secrets/db_password
ENV API_KEY=changeme
ENV SECRET_KEY_BASE_DUMMY=1
USER postgres
"""}, language="dockerfile"),
    # ---------------------------------------------------------------- Dockerfiles: privileges
    case("docker-user-root-explicit", "excessive_privileges", "flagged", {"Dockerfile": r"""FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
USER node
RUN npm run build
USER root
CMD ["node", "dist/server.js"]
"""}, language="dockerfile", line=7),
    case("docker-no-user-scratch", "excessive_privileges", "flagged", {"Dockerfile": r"""FROM golang:1.23 AS build
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM scratch
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
"""}, language="dockerfile", line=4),
    case("docker-user-from-variable", "excessive_privileges", "none", {"Dockerfile": r"""FROM node:20-alpine
ARG APP_UID=10001
RUN adduser -D -u "$APP_UID" app
USER ${APP_UID}
CMD ["node", "server.js"]
"""}, language="dockerfile", note="A user chosen by a build argument is unknown, never assumed root."),
    case("docker-nonroot-base-image", "excessive_privileges", "none", {"Dockerfile": r"""FROM golang:1.23 AS build
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
"""}, language="dockerfile"),
    case("docker-devcontainer", "excessive_privileges", "none", {".devcontainer/Dockerfile": r"""FROM mcr.microsoft.com/devcontainers/python:3.12
RUN pip install --no-cache-dir pre-commit
"""}, language="dockerfile", note="Dev containers choose their user in devcontainer.json."),
    # ---------------------------------------------------------------- Dockerfiles: unpinned images
    case("docker-from-tag", "unpinned_dependency", "flagged", {"Dockerfile": r"""# Build image
FROM node:20-alpine
USER node
"""}, language="dockerfile", line=2),
    case("docker-from-implicit-latest", "unpinned_dependency", "flagged", {"Dockerfile.prod": r"""FROM --platform=linux/amd64 nginx
USER nginx
"""}, language="dockerfile", line=1),
    case("docker-copy-from-image", "unpinned_dependency", "flagged", {"Dockerfile": r"""FROM alpine:3.20@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d
COPY --from=ghcr.io/astral-sh/uv:0.4 /uv /bin/uv
USER 65534
"""}, language="dockerfile", line=2),
    case("docker-stage-references", "unpinned_dependency", "none", {"Dockerfile": r"""FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d AS base
RUN useradd -m app

FROM base AS deps
RUN pip install --no-cache-dir flask

FROM deps
COPY --from=base /etc/passwd /etc/passwd
USER app
"""}, language="dockerfile"),
    case("docker-template-placeholder", "unpinned_dependency", "none", {"docker/Dockerfile.j2": r"""FROM {{ base_image }}
RUN make install
USER {{ app_user }}
"""}, language="dockerfile", note="Template placeholders are not image references."),
]

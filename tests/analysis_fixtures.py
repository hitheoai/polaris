"""Original synthetic static-analysis fixtures only; never execute these snippets."""

SQL_BAD = '''export function search(req, db) {
  return db.query("SELECT * FROM products WHERE name = '" + req.query.name + "'");
}
'''
SQL_GOOD = '''export function search(req, db) {
  return db.query("SELECT * FROM products WHERE name = ?", [req.query.name]);
}
'''
COMMAND_BAD = '''import { exec as execute } from "node:child_process";
export function run(req) {
  execute("printf " + req.query.message);
}
'''
COMMAND_GOOD = '''import { execFile } from "node:child_process";
export function run(req) {
  execFile("/usr/bin/printf", ["%s", req.query.message], { shell: false });
}
'''
SPAWN_BAD = '''import * as cp from "child_process";
export function run(req) {
  cp.spawn("/usr/bin/printf", [req.query.message], { shell: true });
}
'''
SECRET_BAD = '''export function report(req, res) {
  const credential = process.env.SESSION_SECRET;
  console.log(credential);
  return res.json({ credential });
}
'''
SECRET_GOOD = '''export function report(req, res) {
  console.log("credential omitted");
  return res.json({ status: "complete" });
}
'''
PATH_BAD = '''import { readFileSync } from "node:fs";
export function download(req) {
  return readFileSync("/approved/" + req.query.filename);
}
'''
PATH_GOOD = '''import { readFileSync } from "node:fs";
export function download(req) {
  return readFileSync("/approved/public.txt");
}
'''
TLS_BAD = '''import https from "node:https";
export const client = new https.Agent({ rejectUnauthorized: false });
'''
TLS_GOOD = '''import https from "node:https";
export const client = new https.Agent({ rejectUnauthorized: true });
'''
GUARD_BEFORE = '''export async function GET(req: Request) {
  await requireAdmin(req);
  return Response.json({ status: "complete" });
}
'''
GUARD_AFTER = '''export async function GET(req: Request) {
  return Response.json({ status: "complete" });
}
'''
PYTHON_COMMAND_BAD = '''import subprocess
def run(value):
    subprocess.run("printf " + value, shell=True)
'''
PYTHON_COMMAND_GOOD = '''import subprocess
def run(value):
    subprocess.run(["/usr/bin/printf", "%s", value], shell=False)
'''
PYTHON_SECRET_BAD = '''import os
def report():
    print(os.environ["SESSION_SECRET"])
'''
PYTHON_PATH_BAD = '''def download(filename):
    return open("/approved/" + filename).read()
'''
PYTHON_TLS_BAD = '''import requests
def load():
    return requests.get("https://example.invalid", verify=False)
'''

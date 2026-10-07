# Changelog

What changed in each Polaris release. Before 1.0, a minor version can change commands and
output formats; the changes are listed here.

## Unreleased

- **The same review now has the same report id.** `report_id` (and the SARIF `reportId`) covered how
  long the review took, so two identical runs got different ids. It no longer does. If your scripts
  compared ids across runs, they can now rely on them.
- **A project reached through a symbolic link gets a clear error** (`path_is_symlink`) from
  `polaris workflow review`, instead of a generic one. Polaris still refuses such paths; on macOS,
  `/tmp` is one, so use `/private/tmp`.
- **`polaris fix --ai` is now validated against a real local model**, and the run found and fixed
  two problems. A model is now asked only for the corrected file; Polaris builds the rest of the
  proposal, so a model chooses no path, hash, finding or command. And Python fixes that stop using a
  value the flagged call read (`execute("... " + name)` turned into `execute("... = %s")`) are refused
  (`fix_drops_a_value`): the re-check alone had accepted them. The first live run, on one 1.5B model
  and seven tasks, is described in `benchmarks/refactor_eval/README.md`; it is a set of findings, not
  a score.
- **`polaris fix` fixes more problems.** New checked fixes: `yaml.load` becomes `yaml.safe_load`; SQL
  built into a DB-API `execute()` call (sqlite3, psycopg2, psycopg, pymysql, MySQLdb,
  mysql.connector) moves its values into parameters, only where each value is plainly a value;
  Node's `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED = '0'` turn certificate
  checks back on; and a GitHub Actions `run:` script reads an untrusted `${{ }}` value from a step
  `env:` entry instead of having it pasted in. Each fix declines anything it can't prove and is
  checked again before it is shown; none of them runs your tests.

## 0.5.0 (2026-10-06)

- **`polaris fix`** fixes some of the problems `polaris check` finds. A fix is shown only after
  Polaris checks the fixed code again, in memory: the problem must be gone and nothing new may
  appear. Nothing is written until you approve that exact fix (`--apply` asks about each one,
  `--approve DIGEST` is for scripts). It needs a Git project and does not run your tests. Today it
  fixes turned-off certificate checks, debug mode left on, and commands built from text in Python,
  plus the one-line edits `polaris check` already offers. `--json` and `--output` give the plan;
  see [docs/fix.md](docs/fix.md).
- **`polaris fix --ai`** (opt-in) asks an AI model you choose for fixes Polaris has none of its own
  for. Settings live in your own `~/.polaris/ai.toml`; the key is read from an environment
  variable and is never printed or saved. You see which files may be sent, how big they are and
  where before anything is sent, and afterwards what was sent. It is refused in CI, and the answer
  goes through the same checks and your approval. No real provider has been validated yet: it is
  tested with scripted responses.
- **`benchmarks/refactor_eval`**: an offline replay of scripted AI answers, which shows the checks
  stop bad answers (and the kind they can't catch), and a `--live` mode that measures your own
  provider.
- **A GitHub Action, `hitheoai/polaris@v1`**, for pull-request comments: two short jobs
  (`mode: analyze` and `mode: publish`) replace copying a workflow and setting a variable. The job
  that reads the code never holds a write token. `fail-on` chooses whether `publish` can fail the
  job (default: never), and `version` pins the Polaris release it installs from PyPI.

## 0.4.0 (2026-10-05)

The first public release. Earlier versions were private previews.

### Check your code

- **`polaris check`**: one command that checks your code and explains each problem in plain
  words: what's wrong, why it matters and how to fix it. Problems are grouped as *fix now*,
  *check this* and *worth a look*. Text, Markdown and JSON (`polaris.check/1`) output, exit codes
  for scripts and CI, folders without Git, and, in a Git project, what you fixed and what's new
  since your last check. `polaris` on its own, in a terminal, runs it.
- **The simple view** (with the `tui` extra): a checking screen, the problems and their fixes,
  and an all-clear screen. `c` copies a fix prompt for your AI and `x` opens the expert view.
  Dark, light and terminal-colour themes; `NO_COLOR` is honoured.
- **`polaris tui`**, the expert view: findings with their source-to-sink paths, a files × checks
  coverage map, the taint walk across files, the attack surface, other tools' results, fix
  previews and an offline preview of pull-request comments.

### With your AI agent

- MCP tools `polaris_check`, `polaris_explain` and `polaris_fix`.
- `polaris setup <editor> --rule` for Claude Code, Cursor, Codex, VS Code, Windsurf and Warp,
  with a `polaris-check` skill for Claude Code, and `--hooks` for Claude Code and Cursor that
  check the agent's changes each time it finishes. `polaris doctor` checks the connection.
- `polaris setup warp --theme` adds two Warp themes that match Polaris.

### Pull requests and other tools

- **Pull-request comments** from your own GitHub Actions runner (`polaris pr plan`,
  `polaris pr publish`): comments on changed lines, one-click fixes only after a re-check
  confirms them, and one summary that lists what wasn't checked. Pull requests from forks are
  reviewed without running their code.
- **`--import-sarif`** shows other tools' SARIF results next to Polaris's own. Polaris never runs
  those tools and doesn't verify their results.

### What it checks

- Sixteen checks across TypeScript and JavaScript (including Next.js, Express, Hono and
  Fastify), Python, Rust (including Tauri, axum and actix), GitHub Actions workflows and
  Dockerfiles. Files in other languages are listed as not checked.
- Reviews of 80 or more TypeScript and JavaScript files run in parallel worker processes, with
  the same results.

### Releases

- Packages are published from GitHub Actions with PyPI Trusted Publishing, and each release
  has Sigstore signatures, build provenance and checksums ([releasing](docs/releasing.md)).
- Report security problems privately through GitHub ([security policy](SECURITY.md)).

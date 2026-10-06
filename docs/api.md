# Polaris REST API

`polaris serve` exposes two separate surfaces:

- `/v1/workflow/*`: bounded static Python/JavaScript/TypeScript review, host-candidate repair
  proposals and non-executing typed action assessment. No model is needed.
- `/v1/review` and `/v1/assess*`: the existing Python/two-check review and experimental
  classifier contracts, unchanged by the broader workflow.

You can run the server on your own machine, or let other machines use it with API keys,
behind your own TLS reverse proxy.
It parses submitted code without importing/running it, defaults to memory-only analysis,
and does not log or persist request bodies. An administrator may explicitly permit private
transient analyzer files; callers cannot opt in through a request. Proposal responses contain
source/diffs, so handle them as confidential content rather than source-free receipts.
Findings never authorize anything. There is **no apply, execute or test-runner endpoint**.

See [review formats](review-format.md), [analyzer scope/data handling](analyzers.md),
[bounded engineering](engineering.md) and [security](../SECURITY.md).

This API is for integrations that send code to a server. To check code on your own computer, or
from an AI agent in your editor, use [`polaris check`](check.md) and the MCP tools in
[editor setup](ide.md).

## Start the server

```sh
# In an application environment:
python -m pip install 'theovex-polaris[api]'
polaris serve --rules-only              # http://127.0.0.1:8780, memory-only workflow
```

The workflow's default required checks include Semgrep-dependent patterns. A
memory-only server therefore reports incomplete coverage for those checks, not a clean
multi-language scan. To permit external analysis, obtain the exact managed macOS ARM64 analyzer separately
as described in [analyzer installation](analyzers.md#analyzer-installation-and-data-boundary), arrange a
usable OS sandbox, and explicitly start:

```sh
polaris serve --rules-only --allow-temporary-analysis \
  --semgrep /absolute/path/to/polaris-analysis/bin/semgrep
```

The server administrator owns this data-handling decision. Source copies are private and
removed on normal cleanup, not securely erased; crashes/backups can retain them. MCP and
Semgrep use separately pinned application/analyzer environments. The intended analyzer
distribution is `1.178.0+theovex.1` (runtime `1.178.0`), not untouched upstream Semgrep.
The `analysis` extra is removed; `[all]` supplies no analyzer. Other platforms have no
qualified graph and remain incomplete. See the exact [delivery contract](analyzers.md).

Without `--rules-only`, the legacy service loads its model once at startup:
`--model PATH`, then `POLARIS_MODEL`, then
`~/.polaris/models/current`. Without a model it still starts: `/health` and `/v1/models` say
so, the default `"engine": "hybrid"` reviews with the static rules alone (and says so in
`notices`), `"engine": "rules"` works, and `"engine": "model"` gets a clear `503`.

If the port is busy, Polaris says so and suggests a free one.

Useful options:

- `--host`: address to listen on. Anything other than this machine (for example `0.0.0.0`)
  requires API keys.
- `--port` (default 8780), `--model`, `--device auto|cpu|mps|cuda`, `--rules-only`.
- `--allow-temporary-analysis`: administrator opt-in to external workflow analysis; off
  by default. `--semgrep` chooses a trusted absolute pinned analyzer executable, not a
  program named by a request.
- `--guard-policy FILE` and `--action-policy FILE`: administrator-owned JSON policies,
  fixed at startup. These are not body fields, source annotations or caller-granted authority.
- `--api-keys FILE`: key file from `polaris serve keys create` (or set `POLARIS_API_KEYS`).
- `--rate-limit PER_MINUTE` (default 60 per key with API keys, unlimited without) and `--burst`.
- `--workers` (reviews at the same time, default 1) and `--queue` (requests allowed to wait,
  default 16). Model reviews always take turns.
- `--max-body-mb` (default 5) and `--max-files` (default 500).
- `--usage-log FILE`: append usage counts as JSON lines.
- `--cors-origin ORIGIN`: allow a browser app from that origin. Off by default.
- `--docs`: also serve interactive docs at `/docs` and `/redoc`. Your browser loads their
  scripts from a CDN, so leave this off on production servers.

## Endpoints

The OpenAPI description is always published at `/openapi.json`. Print it with
`polaris serve openapi`.

| Method and path | What it does |
|---|---|
| `GET /health` | Whether the server is up, a model is loaded, and keys are required. No key needed. |
| `GET /v1/models` | The loaded model (version, release status, supported checks, identity, per-check flag thresholds) and which engines work. |
| `GET /v1/capabilities` | Languages, checks, engines, limits, result meanings, and the assessment registry. |
| `GET /v1/usage` | Usage counts for the calling key since the server started. |
| `GET /v1/workflow/capabilities` | Actual static-analyzer availability, versions, rule-pack identity, language/check matrix and limitations. |
| `POST /v1/workflow/review` | Review complete submitted file contents with coverage and snapshot binding. |
| `POST /v1/workflow/propose` | Re-review supplied context and validate a host candidate; returns a proposal, never applies it. |
| `POST /v1/workflow/action` | Compare a typed proposed action with administrator policy; nothing executes. |
| `POST /v1/review` | Legacy Python diff/files/snippet review; returns `polaris.review/0.1.0` or SARIF. |
| `POST /v1/assess` | One experimental `polaris.assessment/0.1.0` request. Returns the contract response. |
| `POST /v1/assess/batch` | Up to 64 contract requests at once; one answer each, in order. The hosted-model client uses it. |

### GET /v1/workflow/capabilities

Returns `polaris.capabilities/0.2.0`. Inspect the exact language/check matrix, required
policy, analyzer availability/version and limitations. Availability is not security accuracy.
The default HTTP runtime disables external analysis. A configured-but-unavailable analyzer,
version mismatch or unusable sandbox must not be interpreted as completed coverage.

### POST /v1/workflow/review

The body is `{"files": [{"path": "app/db.py", "content": "...", "before": "..."}], "config": {...}}`.
Only `files` is required. Labels must be unique portable relative paths; they never select
server files. `before` is optional, but guard-regression checks need complete before/after
evidence. The workflow endpoint does not accept the legacy `code`, `diff`, `engine` or
`format` alternatives.

Optional `config` fields are `checks`, `include`, `exclude`, `max_files`, `max_file_bytes`,
`max_total_bytes`, `max_units` and `max_findings`. See [analyzers](analyzers.md) for the default
five checks and bounded patterns. `api_authorization` requires administrator-established
guard policy; absent policy is not evidence that authorization was checked. Narrowing
`checks` is an explicit scope choice, not a full-coverage claim.

```sh
# Intentionally requests only the two in-process Python checks:
curl -s http://127.0.0.1:8780/v1/workflow/review \
  -H 'Content-Type: application/json' \
  -d '{"files":[{"path":"app/ping.py","content":"import os\n\ndef ping(host):\n    os.system(\"ping -c 1 \" + host)\n"}],"config":{"checks":["sql_injection","command_injection"]}}'
```

The response is `polaris.workflow/0.1.0`, containing:

- `status`: `complete`, `incomplete`, `stale` or `error`; not a risk verdict.
- `finding_count`: flagged findings only. Inspect all `review.findings` and non-OK results.
- `review`: `polaris.review/0.2.0`, including per-file/check `coverage`, analyzer
  `capabilities` and provenance. Coverage rows are `checked`, `not_checked` or `partial`,
  with reasons and required/advisory status.
- `snapshot.kind="submitted_content"` and `snapshot.fresh=null`: the server binds supplied
  bytes only, not the client's current worktree. No related server filesystem context is read.
- `tests_status="not_run"`, `changes`, bounded `context` metadata and notices.

HTTP 200 means a report was produced, not that its coverage is complete or that findings are
resolved. An empty finding list alone is never a clean-review signal.

### POST /v1/workflow/propose

Send the same `files` and optional `config`, plus `candidate`:

- `edits`: one to eight `{path, before_sha256, replacement, finding_refs}` entries.
  `replacement` is the complete proposed UTF-8 content, not an executable patch.
- `rationale`: bounded explanation of the host candidate.
- Optional `expected_snapshot_digest`: binds the expected supplied-content review.
- Optional `verification_commands`: typed `ProcessAction` proposals, never run.

The service performs a fresh review, checks that finding references really belong to each
edited path, and returns `polaris.proposal/0.1.0` with the source/diff and exact proposal
digest. It does not invoke a generator, apply edits, infer consent or prove repair correctness.
See `polaris workflow schema candidate` and [engineering](engineering.md) for strict schemas,
hashes, size/path/secret constraints and limitations.

A submitted-content proposal cannot be applied to a local worktree. Review/capture the
actual local workspace, create a new worktree-bound proposal and obtain approval of its new
digest. This API has no remote apply or verify endpoint.

### POST /v1/workflow/action

Send an `ActionRequest` with an `action` of kind `process`, `filesystem` or `network`;
`polaris workflow schema action_request` describes the exact executable/argv, path or URL
fields. Shell strings are not a supported action form.

Action policy is separate administrator configuration, never a request field. No policy
normally yields `needs_review`. The response is `polaris.action-review/0.1.0`:
`within_declared_scope`, `out_of_scope` or `needs_review`, with bounded reasons, and always
`authorized=false`, `executed=false`, `policy_changed=false`, `scope_only=true`. An exact
allowlist match is not a guarantee of actual program effects or permission to execute it.

Workflow requests cannot configure a server root, analyzer executable, trusted policy,
provider URL, approval or a command runner. All four routes use the server's normal
authentication/rate/queue guards; a tool request is not a trusted policy channel.

### POST /v1/review (legacy)

Send exactly one of:

- `{"diff": "..."}`: a unified diff. Only the diff's lines are available, so functions are
  reviewed from their hunks, and the report says so. Send whole files for full context.
- `{"files": [{"path": "app/db.py", "content": "...", "before": "..."}]}`: whole files.
  `before` (the previous version) is optional. `path` only labels findings; the server never
  reads its own disk.
- `{"code": "...", "path": "app/db.py"}`: a snippet; `path` is optional.

Optional fields:

- `"engine"`:
  - `"hybrid"` (default): the static rules decide every result, and the model adds a second
    opinion to each finding (`second_opinion`) that never changes it. Functions the rules pass
    but the model flags come back as `ok` findings with a flagged second opinion.
  - `"model"`: the model alone decides.
  - `"rules"`: static rules only; no model needed.
- `"format"`: `"json"` (default) or `"sarif"` (SARIF 2.1.0 for code-scanning tools).
- `"config"`: `{"checks": [...], "policy": [...], "flag_threshold": 0.8}`. Policy statements are
  trusted context about your own code, for example "Admin scripts run with trusted arguments."
  When you send a policy, the report's `policy_source` is `"request"`. This legacy classifier
  context cannot grant action/apply permission or change the workflow's administrator policy.

```sh
curl -s http://127.0.0.1:8780/v1/review \
  -H 'Content-Type: application/json' \
  -d '{"code": "import os\n\ndef ping(host):\n    os.system(\"ping -c 1 \" + host)\n", "engine": "rules"}'
```

The answer is a `polaris.review/0.1.0` report. Each finding has the file, line range, function,
check, result, estimated risk and threshold (model engine), a plain message, fixed guidance for
the check, the static facts behind it, and, in hybrid reviews, the model's `second_opinion`
(`result`, `risk`, `reason`). `summary.second_opinion_disagreements` counts results where the
model and the rules clearly disagree (one flags, the other finds nothing):

```json
{
  "format": "polaris.review/0.1.0",
  "model": {"engine": "rules", "release_status": "not_applicable"},
  "summary": {"files_reviewed": 1, "units_total": 1, "results": {"flagged": 1, "ok": 1}},
  "findings": [{
    "path": "snippet.py", "start_line": 3, "end_line": 4, "symbol": "ping",
    "check_id": "command_injection", "result": "flagged", "risk": null,
    "message": "Likely command injection: an untrusted value is built into a shell command.",
    "guidance": "Pass the command as a list without shell=True, ...",
    "details": ["line 4 os.system: process execution. Command: concatenation using host (untrusted). ..."]
  }],
  "notices": ["Rule engine: simple static rules only, no model."]
}
```

Results: `flagged` (at or above the threshold), `ok` (not a safety guarantee), `needs_context`,
`uncertain`, `unsupported`, `too_large` and `error`. "Needs context" and "not supported" are
always reported, never counted as passing.

### POST /v1/assess (experimental classifier)

The body is a `polaris.assessment/0.1.0` request (see [contract.md](contract.md) and
`polaris schema request`). The answer is the contract's assessment or error envelope. HTTP
status: 200 for an assessment, 400 for input errors, 413 when the request exceeds the
contract's 1 MiB limit, 503 when no usable model is loaded, 500 for other runtime errors. The
response reports the model's release status, so experimental models are always visible.

### POST /v1/assess/batch

`{"requests": [...]}` with 1 to 64 contract requests. The answer is `{"results": [...]}`: one
assessment or contract error envelope per request, in the same order, so one invalid request
doesn't fail the others. HTTP status is 200 whenever the batch was processed, and 503
`model_unavailable` when no model is loaded. Usage counts each request as one assessment.
This is what `polaris review` uses when signed in to the [hosted model](remote.md).

## Errors

Every other error is a typed envelope with no stack trace and no echo of what you sent:

```json
{"kind": "api_error", "code": "invalid_request", "message": "...", "retryable": false, "fields": ["engine"]}
```

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_json` | 400 | Not valid JSON. Duplicate keys, NaN and Infinity aren't allowed. |
| `invalid_host` | 400 | A local server received a request for another host name. |
| `unauthorized` | 401 | Missing or wrong API key. |
| `not_found`, `method_not_allowed` | 404, 405 | Wrong address or method. |
| `payload_too_large` | 413 | Body over the limit, or JSON nested too deeply. |
| `too_many_files` | 413 | More files than `--max-files`. |
| `unsupported_media_type` | 415 | Send `Content-Type: application/json`. |
| `invalid_request` | 422 | The JSON doesn't match the endpoint; `fields` names the problems. |
| `rate_limited`, `queue_full` | 429 | Too many requests for this key, or the server is busy. See `Retry-After`. |
| `model_unavailable` | 503 | No model is loaded; the message says how to install one. |
| `internal_error` | 500 | Something failed on the server; only its type is logged. |

## Limits

- Request body: 5 MB (`--max-body-mb`). Files per request: 500 (`--max-files`).
- Legacy review file: 2 MB (from the review settings). Larger files are skipped and counted as
  `file_too_large` in the report, not rejected.
- Workflow review defaults: 256 files, 500,000 bytes per file, 4,000,000 source bytes,
  5,000 Python units and 1,000 findings. Exhaustion produces explicit incomplete coverage.
  Workflow request validation accepts at most 500 unique file labels; repair context accepts
  at most 64 files, and the stricter bounded engineering limits also apply.
- JSON: at most 16 levels deep and 50,000 items; strict parsing as above.
- Functions over the model's 2,048-token limit are reported as `too_large`, never cut.

## API keys

Keys are needed whenever the server listens beyond this machine, and can be used locally too.

```sh
polaris serve keys create --file keys.json --name ci    # prints the key once
polaris serve keys list --file keys.json                # names and IDs only
polaris serve keys revoke --file keys.json KEY_ID       # then restart the server
polaris serve --host 0.0.0.0 --api-keys keys.json
```

The key file holds only a salted hash of each key (HMAC-SHA256; keys are 256-bit random
values). It is written with owner-only permissions. Clients send
`Authorization: Bearer <key>`. Instead of a file, `POLARIS_API_KEYS` can hold the file's path or
comma-separated `id:salt:hash` entries (printed by `keys create`); it never takes raw keys.

## Rate limits, queue and usage

- Each key has a token bucket: `--rate-limit` requests per minute with bursts up to `--burst`.
  `keys create --rate-limit N` sets a different limit for one key (0 means unlimited).
- At most `--workers` reviews run at once and `--queue` more may wait; beyond that the server
  answers `429 queue_full` at once instead of piling up work.
- `GET /v1/usage` shows the calling key's counts: requests, rejected requests, reviews,
  assessments, files reviewed, functions reviewed and functions assessed.
- With `--usage-log FILE`, one JSON line per request records the time, key ID, method, endpoint,
  status, time taken and those counts. Never code, file names or request bodies.
  `polaris serve usage FILE` prints totals per key.

## Clients

The clients expose the workflow separately from legacy methods.
Python accepts a corresponding typed request model or mapping and returns typed models:

```python
from polaris.client import PolarisClient

client = PolarisClient("http://127.0.0.1:8780")
capabilities = client.workflow_capabilities()
report = client.review_workflow({
    "files": [{"path": "app/db.py", "content": source}],
    "config": {"checks": ["sql_injection", "command_injection"]},
})
print(report.status, report.review.coverage.complete, report.tests_status)
```

`propose_repair(request)` returns a `PatchProposal`; `review_action(request)` returns an
`ActionReview`. The equivalent TypeScript methods are `workflowCapabilities()`,
`reviewWorkflow(input)`, `proposeRepair(input)` and `reviewAction(input)`, returning
`WorkflowCapabilities`, `WorkflowReport`, `PatchProposal` and `ActionReview`.
There is no remote apply or execution client method. See the
[TypeScript guide](../clients/typescript/README.md) for its exports and build commands.

Legacy Python (`polaris.client`, HTTP transport uses only the standard library):

```python
from polaris.client import PolarisClient

client = PolarisClient("http://127.0.0.1:8780")        # api_key="..." when required
report = client.review_code(open("app/db.py").read(), path="app/db.py")  # engine defaults to hybrid
for finding in report.findings:
    print(finding.result, f"{finding.path}:{finding.start_line}", finding.message)
```

Legacy TypeScript (`clients/typescript`, package `@theovex/polaris`, not published):

```ts
import { PolarisClient } from "@theovex/polaris";

const polaris = new PolarisClient({ baseUrl: "http://127.0.0.1:8780" });
const report = await polaris.reviewDiff(diffText, { engine: "rules" });
```

Build it with `cd clients/typescript && npm install && npm run build`. Both clients send an API
key only over HTTPS or to this machine, refuse redirects, and return typed reports. The
package also ships `openapi.json` for generating clients in other languages; a test keeps it in
step with the server.

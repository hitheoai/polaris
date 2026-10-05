# @theovex/polaris

A typed `fetch` client for the Polaris REST API (`polaris serve`). The development source
adds bounded static workflow review, host-candidate repair proposals and non-executing
action assessment, separately from the legacy Python/two-check review and experimental
classifier. It works in Node.js 18+ and browsers. It is **not published** (`"private": true`);
build it from this source and use a compatible development server.

## Development workflow

```ts
import { PolarisClient, type WorkflowReport } from "@theovex/polaris";

const polaris = new PolarisClient({ baseUrl: "http://127.0.0.1:8780" });
const capabilities = await polaris.workflowCapabilities();
const report: WorkflowReport = await polaris.reviewWorkflow({
  files: [{ path: "src/handler.ts", content: source, before: previousSource }],
});

console.log(capabilities.matrix, report.status, report.review.coverage, report.tests_status);
for (const finding of report.review.findings) {
  console.log(finding.result, `${finding.path}:${finding.start_line}`, finding.message);
}
```

Workflow methods and their exported types:

- `workflowCapabilities(): Promise<WorkflowCapabilities>`: actual analyzer versions,
  availability, language/check matrix and rule-pack provenance.
- `reviewWorkflow(input: WorkflowInput): Promise<WorkflowReport>`: the
  `polaris.workflow/0.1.0` envelope, with nested `WorkflowReviewReport`
  (`polaris.review/0.2.0`), coverage, snapshot and `tests_status: "not_run"`.
- `proposeRepair(input: WorkflowRepairInput): Promise<PatchProposal>`: re-review supplied
  files and validate a host `CandidateRequest`; returns a digest-bound proposal, not an edit.
- `reviewAction(input: ActionRequest): Promise<ActionReview>`: assess typed
  process/filesystem/network scope under administrator-owned policy, never execute it.

`WorkflowInput` has `files: FileInput[]` and optional `config: WorkflowSettings`.
Each file has a unique portable relative label, `content` and optional `before`; no label
is resolved on the server. Settings cover `checks`, `include`, `exclude` and bounded
file/byte/unit/finding limits, not a trusted policy, server root, analyzer executable or
provider URL. The workflow does not accept legacy `engine`, `code`, `diff` or `sarif` options.

The default five checks cover selected Python/JavaScript/TypeScript static patterns, not
whole-program security. `WorkflowCheck` also includes `api_authorization`, which requires
explicit administrator-established guard policy and before/after evidence. Missing policy
is not proof of authorization. Broader patterns do not expand the Preview classifier's domain.

The server defaults to memory-only analysis. JavaScript/TypeScript and other
Semgrep-dependent checks in the example remain incomplete unless the administrator
explicitly enables `--allow-temporary-analysis` with a trusted pinned analyzer and usable
OS sandbox. Clients cannot enable temporary source storage through a request.
The analyzer is managed-only on macOS ARM64: distribution `1.178.0+theovex.1`,
runtime `1.178.0`, in a separate exact graph. The `analysis` extra is removed.
Capability `distribution_version` and `identity_digest` are distinct from runtime `version`;
metadata identity is not full installed-payload integrity or release qualification.
See [server setup](../../docs/api.md#start-the-server) and [analyzers](../../docs/analyzers.md).

Do not treat HTTP success or `finding_count === 0` as a clean review. Check `status`,
`review.coverage`, every non-OK finding and omissions. A submitted-content snapshot has
`fresh: null`: it does not attest the current client worktree.
`WorkflowRepairInput` adds `candidate` with one to eight complete replacement edits,
exact `before_sha256`, observed per-path `finding_refs`, `rationale`, and optional
`expected_snapshot_digest` / typed `verification_commands`. Commands remain proposals;
there is no remote apply, exec or test-runner method. Returned proposal source/diffs need
confidential handling. A supplied-content proposal must be rebound to an actual local
workspace and freshly approved before a separate local apply.

`ActionReview` always has `authorized: false`, `executed: false`, `policy_changed: false`
and `scope_only: true`. Missing policy is `needs_review`, not approval. Static re-verification
is not a behavioral test; a separately approved isolated fixture runner is outside this client.
See [engineering contracts](../../docs/engineering.md) and
[review formats](../../docs/review-format.md).

## Legacy Python review and classifier

```ts
import { PolarisClient, PolarisApiError } from "@theovex/polaris";

const polaris = new PolarisClient({ baseUrl: "http://127.0.0.1:8780" }); // apiKey: "..." when required

const report = await polaris.reviewFiles(
  [{ path: "app/db.py", content: source }],
  { engine: "rules" },
);
for (const finding of report.findings) {
  console.log(finding.result, `${finding.path}:${finding.start_line}`, finding.message);
}

try {
  await polaris.reviewCode(source, { engine: "model" }); // needs a model on the server
} catch (error) {
  if (error instanceof PolarisApiError && error.code === "model_unavailable") {
    // The message says how to install a model; engine "rules" works without one.
  }
}
```

Legacy/service methods: `health`, `models`, `capabilities`, `usage`, `review`, `reviewCode`, `reviewDiff`,
`reviewFiles`, `sarif`, `assess` and `assessBatch` (up to 64 requests). Reviews use the server's
default `"hybrid"` engine unless you pass one. Errors arrive as `PolarisApiError` with the
server's typed `code`, `retryable` and `retryAfterSeconds`. Contract errors from `assess` and
`assessBatch` are returned, not thrown.

## Transport and build

The client sends an API key only over HTTPS or to this machine, and refuses redirects so a key
is never re-sent elsewhere. API errors from workflow methods also throw `PolarisApiError`.
Findings estimate risk; they never grant permissions. These TypeScript exports describe
the response contracts, not independent security or behavioral validation.

`openapi.json` is the server's OpenAPI description (regenerate with
`polaris serve openapi > clients/typescript/openapi.json`); a Polaris test keeps it current.

```sh
npm install
npm run build     # tsc → dist/index.js and dist/index.d.ts
npm run check     # typecheck without emitting files
```

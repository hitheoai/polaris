# The hosted Polaris model

This guide describes the legacy Python/two-check classifier. [`polaris check`](check.md) and the
[static workflow](../README.md#advanced-the-full-review-and-bounded-repairs) are separate and
do not run classifier or coding-provider inference by default.

Polaris can use its model in two ways:

- **Hosted.** Sign in with an API key and the model runs on the Polaris API. Nothing heavy is
  installed: the package is about 130 KB, with no PyTorch and no model download, and model
  updates reach you without reinstalling anything.
- **Local.** Companies with a self-hosting license install the model files (`polaris model
  install`) and it runs on their own machines. Nothing is sent anywhere.

Either way, parsing, the prefilter, the static rules and the report always run on your machine.

> The hosted API is in early access. `https://api.polaris.theovex.com` is the default address
> for when it opens; until then, keys and addresses come from TheoVex directly.

## Sign in

```sh
pip install theovex-polaris     # the [model] extra isn't needed for the hosted model
polaris login                   # paste your API key; typing is hidden
polaris whoami                  # which API and key reviews use, and your usage
polaris review                  # now with the hosted model's second opinion
polaris logout                  # forget the saved key
```

`polaris login` checks the key with the API first, then saves it to
`~/.polaris/credentials.json`, readable only by you. It never prints the key. In CI and
containers, set `POLARIS_API_KEY` instead; it takes precedence over the saved key.
`POLARIS_API_URL` (or `polaris login --api-url`) points Polaris at another Polaris API, for
example one your company runs with `polaris serve` and `polaris serve keys create`.

## What is sent, and what isn't

Polaris parses your code on your machine and finds the functions that make SQL or
process-execution calls. Only those functions are sent, one assessment request each, holding:

- the function's source code, and its previous version when it changed;
- its file path and first line number;
- Polaris's static data-flow notes about it (for example, "the query is built from a parameter");
- your policy statements from `.polaris.toml`, if you wrote any.

Nothing else leaves your machine: no other functions, no other files, no git history. In our
tests, 3 of the 313 functions in one application were sent, and 50 of 2,779 in a sample of the
Python standard library. Codebases without SQL or process calls send nothing at all.

Every report says when the hosted model was used ("The model ran on the Polaris API...").
The legacy `/v1/assess*` requests used by this classifier are reviewed in memory without a
review cache or request-body logging; usage records hold counts only. The same server's
separate workflow API defaults to memory-only analysis, but an administrator may explicitly
allow private temporary source copies for external analysis. Cleanup is not secure erasure;
crashes/backups can retain those copies. A request cannot enable this mode. Review the
deployed server's data-handling policy and [SECURITY.md](../SECURITY.md), rather than assuming
a blanket no-disk-write promise for every workflow configuration.

## Choose where the model runs

`polaris review`, `polaris scan` and `polaris mcp` take `--model-source`:

- `auto` (default): the hosted model when you're signed in, unless you named a local model
  with `--model` or `POLARIS_MODEL`; otherwise an installed local model.
- `local`: only a model on this machine. The Polaris API is never contacted.
- `remote`: only the hosted model. If you aren't signed in, Polaris says so.

`polaris serve` always uses a local model.

## Editors

The development source's `polaris setup cursor` (or `warp`, `claude-code`, `vscode`,
`windsurf`) generates an MCP launch pinned to `--model-source local`. Signing in does not
silently enable hosted inference for that generated server. Older or manually configured
launches may still use `auto`; inspect the actual configuration.

For hosted legacy second opinions, explicitly select `--model-source remote` and a
model-capable legacy engine (`hybrid` or `model`) in the approved server launch, preserving
the trusted executable, project root and normal client permissions, then restart the server.
`--engine rules` does not use a model. The new static workflow and completion hooks do not
start hosted classifier or coding-provider inference. See [editor setup](ide.md).

## CI

Set `POLARIS_API_KEY` from your CI system's masked secrets; it takes precedence over a saved
key. PyTorch and the model aren't installed, so the job starts in seconds. On GitLab, add the
variable in the project's settings and include the template. See [CI and hooks](ci.md).

## When the API can't be reached

- With the default hybrid engine, the static rules still decide every result. The report
  says the model's second opinion was unavailable and why.
- With `--engine model`, `--no-model` decides: `fail` (exit 3, the default), `skip` or `rules`.
- Polaris tries a rate-limited or busy request up to three times, waiting as `Retry-After`
  asks. After a connection failure it stops trying for 30 seconds, so a scan never waits for
  one timeout after another.
- Functions the API couldn't assess are reported as `error` results that say why, never as
  OK. Add `error` to `--fail-on` to fail the job on them.

`polaris whoami` shows whether the key still works.

## Same model, same results

The hosted API runs the same model and review format. Reviews through it gave the same results
as the local model, function by function. Risk scores can differ in the last decimal places,
because the model's arithmetic depends slightly on which functions it processes together; no
result changed. The local review cache works in both modes, so unchanged functions aren't sent
again.

## For integrators

The client uses two endpoints, both in the [REST API](api.md) and `openapi.json`:

- `GET /v1/models`: the model's identity, supported checks and per-check flag thresholds.
- `POST /v1/assess/batch`: up to 64 `polaris.assessment/0.1.0` requests in one call, with one
  answer each, in order.

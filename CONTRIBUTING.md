# Contributing to Polaris

Thank you for helping. Polaris reviews code for security problems with deterministic checks that
run on your machine: `polaris check` uses no AI model and sends nothing anywhere. Changes keep it
that way.

## Report security problems privately

Please don't open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Set up

You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked --extra api --extra mcp --extra tui
```

## Check your change

CI runs these on every pull request and every push to `main`:

```sh
uv run --no-sync ruff check .
uv run --no-sync mypy src
uv run --no-sync pytest -q
```

The tests run offline and never download a model. The terminal views are covered by golden
screenshots in `tests/tui_golden/`: after an intended change to what they show, regenerate them
with `POLARIS_TUI_UPDATE_GOLDEN=1 uv run --no-sync pytest -q tests/test_tui_*.py` and look at
every changed image before you commit it.

Polaris can review your change too: `uv run --no-sync polaris check`.

## Pull requests

- Keep each pull request to one change, with tests for new behavior and for every bug fixed.
- A new or changed check needs both vulnerable cases and safe look-alikes. Never edit the
  held-out cases in `benchmarks/workflow_corpus/` to make them pass: when a change fixes one,
  move it to the development split.
- Don't add network access, telemetry or implicit downloads to review paths.
- Say which checks you ran, and anything you couldn't run.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).

## Code of conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

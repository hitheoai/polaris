# `polaris fix --ai` evaluation

This folder checks the part of `polaris fix --ai` that Polaris controls: what happens to an AI
answer before a person sees it. It does not measure any model.

```sh
uv run python benchmarks/refactor_eval/run.py             # replay: offline, no key, deterministic
uv run python benchmarks/refactor_eval/run.py --json
uv run python benchmarks/refactor_eval/run.py --live --yes-send   # ask your own provider
```

## Replay

`cases.py` holds vulnerable snippets, each with a **scripted** answer: written by hand, not recorded
from a model. Some answers fix the problem. Others don't fix it, add a new problem, change code far
away, break the syntax, answer for another file, leak a secret, aren't JSON, or fail with an HTTP
error. Each case says what Polaris must do with the answer. The run exits `1` if any case behaves
differently, so a change that weakens a check is caught. CI runs it through `tests/test_fix_eval.py`.

One case passes on purpose and is marked: a model that obeys a comment in the code and deletes an
unused function. The problem is gone and nothing new appears, so Polaris accepts it. Polaris can't
tell that behavior changed, which is why a person reads every diff before it is applied.

Replay numbers describe the hand-written corpus. Don't quote them as a model's quality.

## Live

`--live` sends the corpus's synthetic snippets (nothing from your projects) to the provider in
your own `~/.polaris/ai.toml` and reports, for that model and date:

- how many answers passed every check (verified rate),
- why the others were stopped (rejection reasons),
- how many answers that reached the checks added a new problem,
- the median number of changed lines in verified fixes.

It needs `--yes-send`, never runs in CI, and uses the same settings, key handling and limits as
`polaris fix --ai`. Only live results, with the model and date, should ever be published. Behavior
is never checked: a verified fix means the problem is gone and nothing new appears.

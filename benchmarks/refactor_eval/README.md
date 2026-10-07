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
away, drop a value the original call used, break the syntax, leak a secret, aren't JSON, or fail
with an HTTP error. One answer carries extra fields that Polaris must ignore. Each case says what
Polaris must do with the answer. The run exits `1` if any case behaves differently, so a change
that weakens a check is caught. CI runs it through `tests/test_fix_eval.py`.

One case passes on purpose and is marked: a model that obeys a comment in the code and deletes an
unused function. The problem is gone and nothing new appears, so Polaris accepts it. Polaris can't
tell that behavior changed, which is why a person reads every diff before it is applied.

Replay numbers describe the hand-written corpus. Don't quote them as a model's quality.

## What the first live run found

The first live run (2026-10-06, `qwen2.5-coder:1.5b` through Ollama on the same computer, so nothing
left it) taught more than it measured. It is seven tasks, far too few for a rate, and a 1.5B model
is small: read these as findings about Polaris, not as a score for any model.

- The model answered the first version of the request with the wrong shape every time: it was
  asked to repeat file hashes and finding ids and got them wrong. Polaris now asks only for the
  corrected file and builds the digest-bound envelope itself (`reply="file"`), so a model controls
  no path, hash, finding reference or command. Whatever else a reply holds is ignored.
- With that fixed, six of seven answers passed the static re-review, and four of those six were
  broken: on the SQL tasks the model replaced `execute("... " + name)` with `execute("... = %s")` and dropped
  `name`, which removes the injection and the value. A constant query looks safe to the re-review,
  so "verified" was wrong. Polaris then refused a fix that stops using a name the flagged call read
  (`fix_drops_a_value`). With that check, 2 of 7 tasks verified, both correct, 4 were stopped
  for dropping a value and 1 still had the problem. The failure is now a scripted regression case.
- The check can still miss things. It reads values in the flagged call's own arguments, in Python,
  JavaScript and TypeScript, including an attribute (`user.name` is not kept by mentioning `user`).
  It does not follow a value into another variable, it skips a name that only a callback reads, and
  it does not know whether code that keeps the value still means the same. Verified still never means
  correct.

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

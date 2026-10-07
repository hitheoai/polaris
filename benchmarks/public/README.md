# Public benchmark harness

A reproducible way to measure Polaris on public, pinned datasets, and to run other tools on the
same inputs. It exists so that any quality claim about Polaris can be checked by someone else.
It does not contain a result by itself. No results are published yet: the first small runs are
being reviewed first, and any published report will carry its date, pinned versions, limits and
denominators. Run the harness below to produce your own.

No AI is used, no API key is read and no repository code is sent to any service. Polaris runs
through its own CLI with a minimal environment. The only network use is fetching the pinned
public commits (and, if you ask for them, the pinned comparison tools) into a cache folder.

## Run it

```sh
uv sync --extra api --extra mcp --extra tui
uv run --no-sync python benchmarks/public/run.py --list-adapters          # datasets and licences, no network
uv run --no-sync python benchmarks/public/run.py --dataset ossf-cve --limit 20 --repeats 3
uv run --no-sync python benchmarks/public/run.py --dataset fixtures --repeats 3
uv run --no-sync python benchmarks/public/run.py --dataset all --with-semgrep --with-zizmor
```

- `--cache DIR` (or the `POLARIS_BENCH_CACHE` variable; default `/tmp/polaris-bench-cache`) is
  where datasets, tool environments and the raw SARIF of every run go. It must be outside the
  repository, is resolved to a real path (Polaris refuses a review root reached through a
  symlink, and `/tmp` is one on macOS) and is never committed.
- `--report-dir DIR` is a new folder for `report.md` and `report.json` (default
  `<cache>/results/<date>`). Existing reports are never overwritten.
- `--limit N` is the number of CVEs; `--repeats N` is how many times each Polaris run is
  repeated for the determinism check.
- `--with-semgrep` and `--with-zizmor` also run those tools. They run only through
  `uv tool run --from <tool>==<pinned version>` with uv's cache inside the benchmark cache:
  nothing is installed globally and nothing needs sudo. Semgrep CE is about 600 MB to
  download; the datasets and Semgrep rules are about 10 MB; each CVE repository is fetched at
  two commits, depth 1 (about 130 MB for 20 CVEs). Without these flags no comparison is run, and
  the report says so.
- The harness needs `git` and, for the comparison tools, `uv`. Do not run it in CI; the tests in
  `tests/test_public_benchmark.py` cover the pure parts offline.

## Datasets

Each adapter pins an exact commit hash and a content digest of what it uses. It refuses data
that does not match (`PinMismatch`) and never vendors or commits dataset content.

- `ossf-cve-benchmark`: the OpenSSF CVE Benchmark labels (`CVEs/*.json`), MIT licence. Each
  label names a public repository, a vulnerable commit, a fixed commit and the file and line of
  the weakness. The first N labels in id order whose two commits fetch cleanly are used; every
  label skipped on the way is listed in the report with its reason. Repositories that were
  removed or made private are skipped this way.
- `github-actions-fixtures`: the workflow files in zizmor's integration test data at tag
  v1.30.1, MIT licence. They carry no machine-readable labels, so this dataset reports what each
  tool found and where the tools agree. It is not an accuracy measure. Fixtures are not audited
  one by one for third-party origin, so reports contain counts and fixture names only.
- `owasp-benchmark-python`: a disabled stub. The dataset is GPL; it is not fetched, not vendored
  and cannot be switched on by a flag. See `pbench_datasets.OwaspPythonStub`.

## How a result is decided

The report repeats these rules; they are defined in `pbench_core.py` and tested.

- Polaris runs on the labelled files only (the rest of the checkout is readable as context).
  A Polaris `flagged` finding is a detection. A `needs_context` finding is a question and is
  counted as an abstention, never as a detection. Results of other tools are all detections.
- A finding matches a label when it is in the same file and the label's line lies within 5
  lines of the finding's span. Rule, check and weakness type are not part of the rule; CWE
  agreement is counted separately.
- A CVE is `detected`, `abstained`, `missed`, `not_analyzed` (the tool did not analyse any
  labelled file: a scope limit, not a miss) or `error`.
- Fix: for detected CVEs, `cleared` means the same rule id no longer fires in the same file at
  the fixed commit. That is not a claim that the fix is right, and no test is run.
- Every rate is printed with its numerator, denominator and a Wilson 95% interval. A rate over
  an empty denominator is not printed.
- Determinism: each Polaris run is repeated; the normalised conclusions (rules, locations,
  states, fingerprints, evidence digests, coverage) must be identical. The whole SARIF files
  of Polaris 0.5.0 and earlier differ in `reportId`, which was derived from the whole review
  including its elapsed time. Later versions leave elapsed time out, so identical runs have
  identical ids. The report gives both digests, whole files and with `reportId` removed, so older
  versions can still be compared.

## Reading the numbers

Read the "What this does not show" section first. In short: a small deterministic slice, not a
random sample; no false-positive rate (labels are not exhaustive); labelled files only; other
tools are only compared where the report lists their pinned version, rule set and raw output;
fix results are not behaviour claims; determinism is shown on one machine for the repeats
listed. Do not quote a number without its denominator and its date.

## Files

- `run.py`: command line and orchestration.
- `pbench_core.py`: SARIF reading, matching, scoring, digests, pins, report rendering (pure).
- `pbench_datasets.py`: dataset adapters and pinned fetching.
- `pbench_tools.py`: Polaris, Semgrep CE and zizmor runners.
- `pbench_report.py`: sections, the tool comparison and report files.

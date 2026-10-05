# Terminal interface (`polaris tui`)

`polaris tui` is an interactive, read-only view of a Polaris review in your terminal. It shows
what Polaris found, how untrusted data reaches each dangerous call, what was and wasn't checked,
and (with `--base`) what the pull-request bot would post. It works offline, uses no model, and
runs nothing from the repository.

This is the expert view. For everyday use, start with [`polaris check`](check.md): its simple
view shows the same check in plain words, and `x` there opens this view on the same check.

## Install

The interface needs the optional `tui` extra ([Textual](https://textual.textualize.io/) 8.2,
MIT-licensed):

```sh
pip install 'theovex-polaris[tui]'      # or, from a source checkout: uv sync --extra tui
```

`[all]` includes it too. Without it, `polaris tui` prints this install hint; `polaris tui --plain`
works without the extra.

## Start it

```sh
polaris tui                              # uncommitted changes in the current repository
polaris tui --staged                     # staged changes
polaris tui --diff main...HEAD           # a revision range
polaris tui --files src                  # existing code: files or directories
polaris tui --base main                  # pull-request preview of HEAD (or --head REV) against main
polaris tui --report review.json         # a saved review, without running a new one
polaris tui --import-sarif semgrep.sarif # also show another tool's SARIF results (untrusted)
```

It takes the same analysis options as `polaris workflow review` (`--root`, `--checks`, `--include`,
`--exclude`, `--guard-policy`, `--no-external-analyzers`, `--analyzer-plugin`, `--import-sarif`,
`--fail-on-imported`). Save a review for `--report` with
`polaris workflow review --format json --output review.json`, or press `w` in the interface.

The interface refuses to start without a terminal on stdin and stdout, or when the `CI`
environment variable is set; it points to `polaris workflow review --format text|json|sarif`
instead. `--plain` prints the same text report as `polaris workflow review` and returns the same
exit code (0 nothing to fix, 1 issues to fix, 2 stale or failed), so it also works in scripts, in
CI and with screen readers.

Other options: `--theme dark|light|ansi-dark|ansi-light` and `--no-mouse` (leave the mouse to the
terminal so its own text selection works). `dark` and `light` use the Polaris website's colours
(its forest-green code windows and its porcelain pages); the ANSI themes use your terminal's own.

To make all of Warp match, `polaris setup warp --theme` adds two Warp themes, Polaris North (dark)
and Polaris Paper (light), which you pick in Settings > Appearance > Themes. Polaris never changes
Warp's settings. The website's code font is IBM Plex Mono; set it in Settings > Appearance > Text
for the same look (the logo is drawn with block characters, so it works in any monospace font).

## Screens

**Trust bar** (always visible): what was reviewed, HEAD, `● FRESH` / `✖ STALE` (live reviews) or
`○ SAVED` (reports), `✓ COMPLETE` / `◐ INCOMPLETE`, `offline · no model`, and the elapsed time.
While a live review runs, it shows `◌ REVIEWING` and the time so far; the interface stays
responsive.

**1 Findings** (the cockpit):

* a file tree with each file's coverage state (`✓ checked`, `◐ partial`, `✗ not checked`,
  `· not applicable`, `⊘ excluded`) and the number of visible issues (`3◆`) and questions (`1?`);
* the findings table: issues (`✖ issue`) first, then "to verify" questions (`? verify`), then
  analysis errors (`! error`). After a title, `✎` means the finding has a suggested one-line
  edit (`f` previews it) and `⇄N` that N imported results from other tools report the same
  weakness at the same place;
* the details of the selected finding: message, the code around it, the source-to-sink path,
  the fix, a suggested one-line edit if there is one, results other tools reported at the same
  place, and the catalog explanation (what, why it matters, how to fix, examples).

The **severity floor** (`s`) applies to flagged issues and starts at high and above, because
flagged medium findings were mostly noise in real-repository triage. "To verify" questions are
exempt: they are shown from medium up as their own group, and `v` hides them. The status line
always says how many issues are below the floor and how many questions are hidden.

**2 Coverage**: a files × checks matrix. Each row starts with the file's overall state before its
name (as in the tree); every other column is one check (`SQ` SQL injection, `CM` command
injection, and so on; the legend is under the matrix on wide terminals). Move the cursor to a
cell to read why it has its state (for example "no analyzer for this language yet"). `u` shows
only files that were not fully reviewed, `l` cycles through languages, `x` shows excluded files
and `a` all of them. The **What ran** panel lists the analyzers and their versions, the checks,
the scope (analyzed, not source code, excluded, not reviewed, related files followed), limits,
imported SARIF files, suppressions and the baseline.

**3 Attack surface**: the entry points the TypeScript/JavaScript analyzer recognized in the
reviewed files: Next.js route handlers (`route.ts` method exports), `pages/api` routes, server
actions (`"use server"`), and Express-, Hono- or Fastify-style registrations
(`app.get("/path", handler)`). For each one: whether an auth guard call was seen in the handler
or its route middleware (`✓ guarded`, `✗ no auth guard`, or `○ public route` when it matches
`[workflow].public_routes` in `.polaris.toml`), the data it reads and writes, how many dangerous
calls it reaches, and the findings inside it. `enter` shows the handler's first finding in
Findings (lowering the severity floor if needed); `o` opens the handler in your editor. This is
evidence for review, not an access-control model: a guard call being present doesn't prove the
authorization is right. Python handlers aren't listed yet, and reports saved before the field
existed have no attack surface.

**4 Other tools**: results imported with `--import-sarif`, next to Polaris's own:
`⇄ corroborated` (another tool reports the same weakness at the same place as a Polaris
finding), `↗ tool only` (grouped by tool; Polaris did not verify these), `✶ Polaris only`,
`⊘ left out` (per SARIF file and reason, for example outside the review's scope), `✗ rejected`
SARIF files, and runs that reported an unsuccessful execution. Imported text is untrusted and
shown as plain text.

**5 PR preview** (`polaris tui --base REV`): what `polaris pr plan` computes for this change,
offline: the gate, the inline comments (on changed lines only) and the summary comment, shown as
the Markdown the bot would post. The first plan uses `pr plan`'s defaults. Change the options and
the plan is recomputed in the background: `i` lowest severity commented inline, `k` comment inline on
"to verify" questions too, `g` lowest severity that fails the gate, `m` inline comments for
imported results (none, security, errors), `e` imported results that fail the gate, `u` re-verify
suggested edits (offered as one-click suggestions only when verified). Earlier verifications are
reused, so changing options doesn't verify the same edit twice. A plan must name a repository
and a pull request, so the preview uses clearly labelled placeholders
(`local-preview/unpublished`, PR #1) that never appear in the comment text. Nothing is
published, and no forge, network or token is used. A saved report can't produce a preview: it
needs the pull request's changed lines and the analyzed text.

**Taint walk** (`t` on a finding): the finding's trace step by step from the untrusted source to
the sink, across files, with the code at each step.

**Fix preview** (`f` on a finding with a suggested edit): the one-line edit in context, and
whether a static re-review with the edit applied no longer detects the finding and reports
nothing new (`✓ verified`, `✗ still detected`, `✚ adds findings`, `? inconclusive`). The
re-review runs the built-in analyzers in memory on the exact analyzed text: nothing is written
or executed, and tests are not run. It needs a live review and allows up to 20 verifications per
review (the limit `pr plan` uses); results are shared with the PR preview. To apply an edit, use
your editor (`o`) or `polaris workflow propose`/`apply` with an approved digest.

## Keys

| Key | What it does |
| --- | --- |
| `?` | keys, glyphs and safety notes (including why any key is unavailable right now) |
| `/` | filter findings by text (title, path, rule, message); `esc` clears |
| `:` or `Ctrl+P` | command palette |
| `1`–`5` | switch tabs |
| `s` | severity floor for issues: high, medium, low, info, critical |
| `v` | show or hide "to verify" questions |
| `r` | run the review again (live reviews) |
| `o` | open the file in `$VISUAL` or `$EDITOR` at the finding's line (see below) |
| `w` | save the review as JSON, always to a new file |
| `t` | taint walk; in the walk `n`/`p` next or previous step, `g`/`G` source or sink, `enter` open the file at that step, `esc` back |
| `f` | fix preview: the suggested edit and whether a re-review confirms it; `o` opens your editor at the edit |
| `y` | copy the prompt for your coding agent |
| `enter` | in the tree: show only that file or folder; in the table: read the details; in the attack surface: show the handler's first finding |
| `i` `k` `g` `m` `e` `u` | in the PR preview: inline floor, questions inline, gate floor, imported inline, fail on imported, verify fixes |
| `Tab` / `Shift+Tab` | move between panes |
| `q` | quit |

The key bar shows the keys of the focused pane; an unavailable key is marked `⊘` with the
reason (for example `⊘ f fix: no fix` when the rule has no deterministic edit). Pressing it shows
the full reason.

### Opening files in your editor

`o` runs the editor named by `$VISUAL`, or else `$EDITOR`. If neither is set, the key bar shows
`⊘ o open: no $EDITOR`, and pressing `o` or `?` says how to set one. The interface reads the
environment it was started with, so set the variable in your shell (or your shell profile, such
as `~/.zshrc`) and start `polaris tui` again:

```sh
export EDITOR="code --wait"     # VS Code (also cursor, codium, windsurf)
export EDITOR=nvim              # or vim, nano, emacs, micro, hx
```

## Safety

* **Read-only.** Nothing from the repository is executed, imported or written. Live reviews are
  the same static reviews as `polaris workflow review`.
* **Only three actions**, each after a key press:
  * `o`: opens your editor. `$VISUAL` (or `$EDITOR`) is split with `shlex` and run without a
    shell, inside the terminal handover. The vi family, nano, emacs, micro and helix get
    `+LINE`; the VS Code family (`code`, `codium`, `cursor`, `windsurf`) gets
    `--goto path:line`; other editors get just the path. The path must resolve to a file inside
    the repository.
  * `y`: copies the agent prompt with OSC 52 and always shows it on screen too, because a
    terminal can't confirm the copy. The prompt is the one the pull-request bot posts: only
    catalog text and validated identifiers, never text from the reviewed code.
  * `w`: writes the report to a new file with private permissions; existing files and symbolic
    links are refused.
* **Inert text.** Paths, messages, code and SARIF text are displayed as plain text. Markup such
  as `[red]` stays literal; ANSI escape sequences and control, invisible or bidirectional
  characters (the "Trojan Source" class) are shown as U+FFFD (`�`), never interpreted. Very long
  lines are cropped.
* **Exact code.** Live reviews show the exact text that was analyzed. For saved reports, a
  worktree file is shown only if its digest matches the one recorded in the report; otherwise
  the snippet stored in the report is shown, marked "changed since the review".
* **Previews stay local.** The PR preview and the fix preview compute in memory and publish,
  write or run nothing; the placeholders in the PR preview are never sent anywhere.
* Errors are fixed codes (`polaris tui: … [invalid_report]`), never exception text.

## Accessibility

* Every state has a glyph **and** a word (`▲ HIGH`, `✓ checked`, `? verify`, `● FRESH`); colour
  is never the only signal.
* Colours come from the Polaris website, and every text colour keeps at least 4.5:1 contrast
  with its background (a test checks this). Because each state also has its glyph and word, no
  colour has to be told apart. `--theme ansi-dark` or `ansi-light` uses your terminal's own 16
  colours, so its high-contrast or colour-blind palette applies. `NO_COLOR` removes colour
  entirely. Warp draws neither italic nor dim text, so emphasis is bold and colour only.
* Designed to work at 80×24; wider terminals get more columns and side-by-side panes.
* Keyboard-first: every action has a key; the mouse is optional (`--no-mouse`).
* Full-screen interfaces don't work well with screen readers: use `polaris tui --plain`,
  `polaris workflow review` (text) or `--format json`.

## Limits

* Saved reports up to 32 MB (and a bounded number of JSON values) are accepted.
* Re-running (`r`), fix verification and the PR preview need a live review; a saved report is
  only displayed. Fix previews verify at most 20 edits per review.
* The attack surface covers TypeScript/JavaScript entry points only (up to 2,000 per review).
* OSC 52 copying and mouse reporting depend on the terminal (in Warp, mouse reporting is a
  setting). Copying is always backed by the on-screen text.
* The editor needs a terminal session that can hand over control (not available in headless or
  web terminals); the interface then says so and runs nothing.
* Glyphs such as `◐`, `◆` and `⊘` are "ambiguous width" characters. Columns line up with the
  usual setting, which draws them one cell wide; a terminal set to draw them double width (an
  option in some CJK setups) shifts the columns.
* Golden screenshots pin the rendering to Textual 8.2; the extra is pinned to `<8.3`.

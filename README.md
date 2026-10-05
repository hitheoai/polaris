# Polaris by TheoVex

Polaris is a free security check for your code and for your AI coding agent. It finds security
problems and explains each one in plain words: what's wrong, why it matters and how to fix it.

- **Local.** `polaris check` runs on your computer: nothing leaves it, and no account is needed.
- **Deterministic.** It uses no AI model, so the same code always gives the same result.
- **Honest.** Polaris reports the problems it finds and lists the files it couldn't check.
  Finding nothing doesn't prove your code is safe.

## Install

Polaris needs Python 3.11 or newer.

```sh
pip install 'theovex-polaris[tui]'
```

or, to install it as a tool with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install 'theovex-polaris[tui]'
```

The `tui` extra adds the interactive view. For AI agents, add the `mcp` extra too:
`'theovex-polaris[tui,mcp]'`.

## Check your code

```sh
cd your-project
polaris check
```

Polaris checks your changes, or your whole project if nothing changed. In a terminal it opens a
simple view:

- **✔ Safe to ship**: nothing to fix now, and every file was checked.
- **✖ Not yet**: there is something to fix before you ship.
- **◐ Not fully checked**: nothing to fix now, but some files couldn't be checked.

Each problem is in one of three groups. **● Fix now** are serious problems. **? Check this** are
questions only you can answer, such as whether a value can come from a user. **○ Worth a look**
are smaller problems. Press Enter on a problem to see the details, `c` to copy the fix for your
AI, `r` to check again and `?` for help. `x` opens the expert view, with everything Polaris knows
(also available as `polaris tui`).

Some useful options:

```sh
polaris check --all            # the whole project
polaris check --staged         # only what you're about to commit
polaris check --files src      # these files or folders
polaris check --plain          # plain text instead of the interactive view
polaris check --json           # the full result, for an AI agent or a script
```

- **Exit codes:** `0` nothing to fix now and everything was checked, `1` something to fix now,
  `2` not fully checked, or the check couldn't run.
- **Since your last check:** in a Git project, each check tells you what you fixed, what's new
  and what's still open. Polaris remembers only problem ids, in Git's private folder.
- **Folders without Git** work too: Polaris checks every file in the folder, skipping dependency
  and build folders such as `node_modules`.
- **`--limit N`** shows up to N problems in full (1 to 50, default 25); the rest are counted.

The full guide is in [docs/check.md](https://github.com/hitheoai/polaris/blob/v0.4.0/docs/check.md).

## Use it with your AI agent

Polaris connects to Claude Code, Cursor, Codex, VS Code, Windsurf and Warp through MCP. In your
project:

```sh
polaris setup claude-code --rule      # or: cursor, codex, vscode, windsurf, warp
polaris doctor claude-code            # check that everything is connected
```

Then ask your agent: **"Check my changes with Polaris."** The agent gets three tools:

- `polaris_check` checks the project and returns everything in one result.
- `polaris_explain` explains a problem in plain and technical words, with examples.
- `polaris_fix` gives the exact fix for one problem.

`--rule` adds a short rule for the agent: after a change, check with Polaris, fix what needs
fixing now, check again until it's clear, and tell you plainly what was found and fixed. It also
tells the agent never to hide or suppress a finding without your OK. For Claude Code, setup adds a
`polaris-check` skill as well. For Claude Code and Cursor in a Git project, `--hooks` makes
Polaris check the agent's changes every time it finishes and hand back what to fix now, for a few
rounds at most. Polaris never edits your files itself.

No MCP? Agents and scripts can run `polaris check --json` and read the result
(`polaris.check/1`): a status, every problem with its location, fix and a ready-to-use prompt,
and the files Polaris couldn't check.

Using Warp? `polaris setup warp --theme` also adds two Warp themes that match Polaris, Polaris
North (dark) and Polaris Paper (light). For the same look, set Warp's font to IBM Plex Mono.

Editor-by-editor steps are in [docs/ide.md](https://github.com/hitheoai/polaris/blob/v0.4.0/docs/ide.md).

## Pull-request comments

Polaris can also review GitHub pull requests from your own Actions runner. It comments on the
lines a pull request changed, offers one-click fixes only after a re-check confirms them, and
posts one summary that also lists what it couldn't check. No Polaris service, account or API key
is involved, and pull requests from forks are reviewed without checking out or running their
code. Preview the comments locally, with no network or token:

```sh
polaris pr plan --root . --base origin/main --head HEAD --repository owner/name --pr 1 \
  --no-external-analyzers --format markdown
```

See [docs/pr-bot.md](https://github.com/hitheoai/polaris/blob/v0.4.0/docs/pr-bot.md).

## What it checks

Polaris reads TypeScript and JavaScript, Python and Rust code, GitHub Actions workflows and
Dockerfiles. It looks for sixteen kinds of problems:

- Users could read or change your database (SQL injection)
- Users could run commands on your server (command injection)
- Users could run their own code inside your app (code injection)
- Attackers could run scripts in your users' browsers (cross-site scripting)
- Your server could be tricked into visiting other addresses (server-side request forgery)
- Links on your site could send people to fake sites (open redirect)
- Users could read or overwrite files on your server (path traversal)
- A password or API key is visible in your code (exposed secret)
- This code runs without checking who is asking (missing authorization)
- Passwords or login codes could be guessed (weak authentication or cryptography)
- A security protection is turned off (unsafe security setting)
- A pull request or issue could take over your GitHub workflow (workflow injection)
- Your workflow runs strangers' code with your secrets (untrusted checkout)
- Something runs with more power than it needs (excessive privileges)
- A tool or image version could change without you knowing (unpinned dependency)
- You download and run a script without checking it (unverified download)

These are static checks of known patterns, not a full security audit. Polaris never runs,
imports or builds your code. Code in other languages is listed as not checked. Exactly what each
check looks for is in [docs/analyzers.md](https://github.com/hitheoai/polaris/blob/v0.4.0/docs/analyzers.md).

## More

- `polaris tui`: the expert view, with every finding's path through the code, a coverage map and
  fix previews ([docs/tui.md](https://github.com/hitheoai/polaris/blob/v0.4.0/docs/tui.md)).
- `polaris workflow review`: the full technical review behind `polaris check`, with JSON, SARIF
  and Code Quality output for CI.
- `polaris --help` lists every command.
- What's new: [CHANGELOG.md](https://github.com/hitheoai/polaris/blob/v0.4.0/CHANGELOG.md). Source
  code and issues: [github.com/hitheoai/polaris](https://github.com/hitheoai/polaris).

## License

Polaris is licensed under Apache-2.0
([LICENSE](https://github.com/hitheoai/polaris/blob/v0.4.0/LICENSE)). Third-party components keep
their own licenses.

# Sandboxed test runner: threat model and design

Status: design for outside review. **No runner code exists.** Nothing in this document is shipped,
and nothing here changes what Polaris does today. Today Polaris parses source and never executes
project code ([engineering.md](../engineering.md), [fix.md](../fix.md)).

Written: 2026-10-06. Facts about other software were read from the sources listed in
[Appendix B](#appendix-b-sources) on that date. Behavior of macOS `sandbox-exec` was observed on one
machine ([Appendix A](#appendix-a-experiments-run-for-this-document)). Every claim is tagged where it
matters:

* **[observed]**: I ran it on the machine described in Appendix A and saw the stated result.
* **[documented]**: I read it in the cited primary document on the date above.
* **[unverified]**: reasoned, remembered or reported by a secondary source, and not checked by me.
  Treat it as a hypothesis that the implementation spike must test.

If you are reviewing this as a security engineer: the questions I most want answered are in
[section 9](#9-open-questions) and the least-verified claims are collected in
[section 10](#10-what-was-verified-and-what-was-not).

## 1. Summary and recommendation

The proposal: an opt-in command that runs a test command **the user types or confirms**, against a
fix or refactor Polaris has already verified statically, inside an isolated throwaway copy of the
worktree, and records `tests: passed | failed | not_run` as evidence beside the static result.

This is the first time Polaris would run code that came from a repository. Everything else it does
is parsing. The test command and the repository's dependencies are untrusted code. The sandbox is
the only thing between that code and the user's files, credentials and network, so the design
treats the sandbox as the product and the test run as the thing it contains.

**Recommendation: GO-WITH-CONDITIONS**, for building an *experimental, default-off, CLI-only*
first version, not for a public release. The conditions are in [section 8](#8-recommendation). In
three sentences:

1. Build a spike first: a deny-by-default sandbox profile on macOS (Seatbelt) and bubblewrap on
   Linux that can run the user's own `pytest` or `npm test` on real repositories without falling back
   to readable-everything, plus a fail-closed self-test that proves network denial, out-of-copy write
   denial and credential-canary read denial before every run.
2. The mechanism Polaris already uses for Semgrep is **not** sufficient for hostile test code: a
   macOS profile of the same shape denies network and writes but leaves every file readable
   **[observed]**, and the Linux variant mounts the whole filesystem read-only, so `~/.ssh` stays
   readable; the runner needs
   a deny-by-default read policy, and if the spike cannot make that work on macOS the answer for
   macOS is `not_run`, not a weaker sandbox.
3. If the owner says no, Phase 1 and Phase 2 of the roadmap are untouched; what is lost is the
   `tests:` evidence level, test-failure feedback for AI repair (B4) and AI refactoring (C3), which
   the roadmap already says Polaris refuses to offer without tests (section 8.3).

## 2. Scope, promises and non-goals

### 2.1 In scope

* One opt-in action: run **one** user-supplied command, **once** per run, in one throwaway copy, with
  no network, against (a) the unmodified snapshot as a baseline and (b) the snapshot with the
  approved-for-testing proposal applied.
* Recording the result in a source-free record bound to the proposal digest.
* Refusing, with a stated reason, whenever the sandbox cannot be proven to enforce.

### 2.2 What the runner would promise

1. Polaris executes only an argument vector the user typed or explicitly confirmed on an interactive
   terminal, shown in full. It is never taken from model output, repository files, repository
   configuration, an API/MCP/hook request or an environment variable.
2. The command runs only inside an isolated copy. The runner never writes to the user's worktree.
   Applying a fix remains the separate, digest-bound approval step that exists today.
3. Before every run, a self-test inside the same sandbox configuration proves (with positive
   controls) that this machine, now, denies network connections, writes outside the copy and reads of
   a planted credential canary. If any check fails or cannot run, nothing runs and the result is
   `not_run` with a reason.
4. The result states exactly what happened: the command, its exit status, limits that fired, which
   limits were enforced and which were best effort, the sandbox backend and its identity, the
   snapshot digests, and that a baseline was or was not run.
5. Output shown to the user is bounded and sanitized. Test output is never treated as a result.

### 2.3 What the runner never promises

* **That the change is correct or that behavior is preserved.** `tests: passed` means: the user's
  own command exited 0 inside the limits, in an isolated copy, with the change applied. It says
  nothing about test quality, coverage, determinism or whether the tests exercise the changed code.
  `behavior_proven` stays `false` in every record, forever
  (`src/polaris/engineering/models.py` already makes it `Literal[False]`).
* **That a hostile repository cannot fake a pass.** The command and the code it loads belong to
  whoever wrote the repository. They can exit 0. The runner defends the *user's machine* against
  that code; it does not authenticate the code's claims. A result is therefore advice for the user
  about their own project, never an automated gate against untrusted contributors.
* **That the sandbox cannot be escaped.** Kernel and sandbox-implementation bugs exist. The design
  limits blast radius and says what remains.
* **That resource exhaustion cannot degrade the machine.** CPU time, memory, disk and process-count
  limits are enforced where the platform allows and disclosed where it does not.
* **That dependencies are safe.** Whatever `pip install` or `npm install` did earlier ran outside
  this sandbox and is out of scope.

### 2.4 Non-goals

* No default behavior. Never on by default, never in CI, never from a fork pull request, never
  from the API, MCP server, editor hooks or agent hooks.
* No network, ever, in the first version. No allowlist, no proxy, no registry access, no dependency
  installation inside the sandbox.
* No discovery of test commands. Polaris never guesses `pytest`, `npm test` or `make test`.
* No AI involvement: test output is not sent to any model in this design. Feeding failures back to an
  AI (roadmap B4) needs its own threat model for output-as-prompt-injection.
* No Windows. No multi-tenant or remote-service use. The runner is a local developer tool.
* No claim of resisting a hostile *local* user or a same-uid attacker who already runs code as the
  user. If one exists, the user's files are already lost.

## 3. Assets, adversaries and trust boundaries

### 3.1 Assets, most to least important

1. **Credentials and keys** on the machine: `~/.ssh`, cloud and package-registry tokens in dotfolders,
   keychains and browser profiles, `.env` files and `.git/config` URLs that embed tokens, and the
   environment variables of the user's running shells.
2. **The user's other files**: the real worktree (including untracked files), other projects,
   documents.
3. **Network position**: the machine's access to the internet, the LAN and loopback services
   (databases, local model servers, container daemons, dev servers, agent sockets).
4. **Machine availability**: CPU, memory, disk, process table, the user's interactive session.
5. **The integrity of the evidence**: that `tests: passed` was produced by the command shown, against
   the code shown.
6. **The user's terminal and, later, any AI that reads output.**

### 3.2 Adversaries

All four are assumed to be able to run arbitrary native code through the test command.

* **A malicious repository or dependency (supply chain).** The repository's tests, `conftest.py`,
  build scripts, `package.json` lifecycle scripts and its installed dependencies in `.venv` or
  `node_modules` all execute when the test command runs. The user cloned it in good faith.
* **A malicious fork pull request.** Someone else's change, reviewed by Polaris on the maintainer's
  machine or in CI. The runner is refused in CI, and on a maintainer's machine a fork's code is just
  the first case again.
* **A prompt-injected AI-generated change.** `polaris fix --ai` produces a candidate from text that
  may contain attacker instructions. The scope gate and re-verifier bound what files change, but the
  *code the change adds* then executes when tests run. Running tests on an AI-written change is
  executing AI-written code.
* **A compromised test command or its dependencies.** The user's own `pytest`, `jest`, `make`, a
  plugin, or a transitive package was backdoored upstream. The command is trusted by the user but
  not by Polaris.

**The test command is untrusted code that runs with the repository's dependencies.** Polaris must
assume it is hostile even when the user typed it.

### 3.3 Out of scope adversaries

A same-uid process already running on the machine; a malicious user with physical access; a
compromised Polaris installation; a compromised OS kernel; hardware side channels (the gVisor
documentation notes that even VMs cannot prevent these, see 5.4).

### 3.4 Trust boundaries

```text
[ user ] ---types/confirms command---> [ Polaris (trusted, unsandboxed) ]
                                          |  1. builds the copy, self-tests the sandbox
                                          |  2. launches the sandbox with a fixed profile
                                          v
                                  ==== sandbox boundary ====
                                  | copy of tracked files   |  untrusted:
                                  | read-only toolchain     |  test command, repository
                                  | private HOME / TMPDIR   |  code, dependencies
                                  | no network, no creds    |
                                  ===========================
                                          | bounded bytes: exit status + output
                                          v
                              [ Polaris sanitizes, records, displays ]
```

Everything that crosses the boundary outward is exactly: the exit status, bounded output bytes, and
timing. Nothing else is read back from the copy.

## 4. Attack surface and abuse cases

Each case lists the attack, the mitigation, and the **residual risk** that remains after it. "Fail
closed" means the runner returns `not_run` with a reason rather than running with a weaker policy.

### 4.1 Filesystem

**A1. Path tricks while building the copy.** A tracked path such as `../x`, an absolute path, a
case-aliased name or an embedded control character tries to land outside the copy.
Mitigation: reuse the exact-spelling rules in `src/polaris/engineering/security.py` (`relative_path`)
and the descriptor-based, no-follow I/O in `src/polaris/engineering/workspace.py`; create files with
`O_CREAT|O_EXCL|O_NOFOLLOW` on directory descriptors, as `semgrep.py` already does. Any violation
aborts the snapshot. Residual: none known beyond filesystem-level bugs.

**A2. Symlinks and hard links in the repository.** A tracked symlink points at `~/.ssh` or `/etc`; a
hard link aliases a file outside.
Mitigation: the copy contains regular files only. Tracked symlinks and files with more than one link
are not copied; they are listed in the result, and if any file the command needs is missing the
command fails visibly. The `workspace.py` reader already rejects `st_nlink != 1`. Residual: tests that
rely on symlinks fail or are skipped, and the result shows what was omitted.

**A3. Symlink planted at run time.** The test creates `link -> ~/.ssh/authorized_keys` inside the copy
and writes through it.
Mitigation: the kernel confines writes regardless of the path used. **[observed]** On macOS a write
through a symlink inside the writable directory that points outside was denied
(experiment 6). Residual: relies on the sandbox being enforced, hence the self-test.

**A4. Writing outside the copy.** Direct writes, `../`, absolute paths, shared `/tmp`, other users'
temporary folders, shell startup files, launch agents, `~/Library`.
Mitigation: writes allowed only under the copy directory (which also holds the private `HOME` and
`TMPDIR`); everything else denied by the kernel policy. **[observed]** On macOS, with
`(deny file-write*)` plus an allow for the copy's resolved path, a write outside failed with
`Operation not permitted` and a write inside succeeded (experiments 2, 3, 7). Two traps found by
experiment: the allow path must be the **resolved** path (`/private/tmp/...`), since a profile built
from `/tmp/...` denied writes even inside the intended directory (experiment 5, fails safe but breaks
the run); and the profile cannot be loosened from inside (experiment 15). Residual: character and
block devices the profile allows (for example `/dev/null`) are writable but harmless.

**A5. Reading credentials and the user's other files.** `cat ~/.ssh/id_ed25519`, `~/.aws/credentials`,
keychain files, browser profiles, the **original worktree** (untracked `.env`, `.git/config` with a
token in a remote URL), other projects, `/private/var/folders` temp data of other apps.
Mitigation: this is the case the existing Semgrep sandbox does **not** cover. **[observed]** under
that profile shape a file outside the writable directory was readable (experiment 4); the Linux
variant in `src/polaris/review/analyzers/process.py` uses `--ro-bind / /`, so the entire filesystem,
including `~/.ssh`, is readable **[documented in code]**. The comment on `sandboxed_command` states
this is "not a claim to sandbox a hostile analyzer binary". The runner must use a **deny-by-default read
policy**: readable are the copy, the system roots a toolchain needs, and explicitly named read-only
toolchain and dependency directories; the original worktree root, `$HOME`, `/tmp`, `/Volumes` and
other users' folders are denied. A folder-level read denial works **[observed]** (experiment 11).
Residual: anything inside an allowlisted system root is readable (that is why the allowlist must be
narrow); the self-test proves denial for a *planted canary*, not for every possible credential;
whether common toolchains run under a deny-by-default read policy is **not yet measured**. If they do
not, macOS support is dropped rather than weakened.

**A6. Reading the original worktree turns silent wrong-code into loud failure.** A pytest run in the
copy imports the project through an editable install or `PYTHONPATH` that points at the *original*
tree, so the tests exercise unmodified code and report a meaningless `passed`.
Mitigation: (a) deny reads of the original worktree root, so such an import fails loudly instead of
silently succeeding; (b) detect editable-install markers and refuse with a reason
(`editable_install_points_outside_copy`). Residual: other mechanisms that load code from a different
location than the copy (a pre-built wheel installed in `.venv` of the *same package*, a vendored
copy) are not detectable by Polaris; the result says "tests ran against the copy plus the installed
environment", not "against the changed code only".

### 4.2 Environment, processes and IPC

**A7. Environment variable leakage.** `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, provider API keys
and similar variables are inherited by default.
Mitigation: the child environment is an allowlist built from scratch (the pattern in
`controlled_environment` and `offline_environment`): a minimal `PATH`, a private empty `HOME`,
`TMPDIR` and XDG directories inside the copy, `LC_ALL=C`, `NO_COLOR=1`, `PYTHONDONTWRITEBYTECODE=1`.
Nothing is forwarded by name from the parent environment. A user who needs a variable types a
literal `NAME=value` flag that is shown in the confirmation. Residual: values the user types.

**A8. Reading other processes' environments and arguments.** Under an allow-default macOS profile a
sandboxed process may still be able to read other same-uid processes' arguments and environment
through `sysctl` and process-info operations. **[unverified]**: I did not test it.
Mitigation: the profile must deny `process-info*` for other processes and restrict `sysctl-read` to
a named allowlist; on Linux a new PID namespace with a fresh `/proc` hides other processes
(bubblewrap README, [documented]). Residual: this is an item for the adversarial suite, not a settled
point.

**A9. Escape through system services (macOS).** With an allow-default policy, a confined process can
usually still reach Mach services. Classes worth testing: the resolver service for DNS, LaunchServices
(`open`), `launchd` job submission, Apple Events (`osascript` driving Terminal or Finder), the
pasteboard. Any of these can cause code to run, or data to leave, *outside* the sandbox. **[unverified]**
for each; I tested none. An open third-party report (apple/containerization issue 737, which is
a user's own account, [unverified]) says Mach IPC could not be blocked for one workload.
Mitigation: deny `mach-lookup` by default with a short named allowlist, deny `appleevent-send`,
`iokit-open`, `system-socket`, `ipc-*` beyond what the self-test shows is required; any denial of
something a toolchain legitimately needs is a spike finding, not a reason to loosen the policy.
Residual: this is the main reason macOS stays "experimental" until externally reviewed, and why the
Seatbelt API's deprecation (5.1) matters.

**A10. Signals and process control against other processes.** A test sends `SIGKILL` to the user's
editor or terminal, or attaches a debugger.
Mitigation: allow signalling only the sandbox's own processes (macOS `signal (target self)` or
same-sandbox); new PID namespace on Linux; refuse debugger-style operations. **[unverified]** on
macOS; adversarial test required. Residual: if the test fails, availability only.

**A11. Orphan and escaped processes.** The test double-forks or calls `setsid` and leaves a daemon,
so a process-group kill misses it. `src/polaris/review/analyzers/process.py` kills the process
**group**; a child that starts a new session is outside it.
Mitigation: on Linux, a fresh PID namespace hides outside processes (bubblewrap README
[documented]) and, with `--die-with-parent` (already used by `process.py`), is expected to take every
process in the namespace down when the parent dies; the exact semantics of that flag are
**[unverified]** here and belong in the adversarial suite. On macOS there is
no PID namespace: the runner polls the process tree during the run and kills all descendants before
and after the parent exits, and the confinement is inherited by every child **[observed]**
(experiment 7), so a survivor stays confined. Residual: on macOS a fast double-fork can outrun
polling and survive as a confined, idle or CPU-burning process. This is disclosed; the adversarial
suite measures it.

**A12. Resource exhaustion.** CPU spin, memory hog, disk fill, fork bomb, output flood, wall-clock
hang.
Mitigation and honest platform facts:

* **Wall clock:** hard timeout, then `SIGKILL` of the process group (as `run_bounded` does) and, for
  the runner, of every descendant found by tree polling. Always enforced.
* **CPU:** `RLIMIT_CPU` applies per process, not per tree; the launcher in `process.py` already sets
  it, along with `RLIMIT_FSIZE` and `RLIMIT_CORE`. Best effort plus wall clock.
* **Memory:** the macOS `setrlimit(2)` page on this machine lists `RLIMIT_CORE, CPU, DATA, FSIZE,
  MEMLOCK, NOFILE, NPROC, RSS, STACK` and no address-space limit **[observed in the local manual]**.
  Treat memory as **not reliably enforceable on macOS**; the runner may poll resident size and kill,
  which is racy. On Linux use cgroup v2 limits (via a `systemd-run --user` scope or a rootless
  container) where available; availability on a given host **[unverified]**.
* **Processes:** `RLIMIT_NPROC` is documented as a limit on simultaneous processes "for this user
  id", so it is shared with every other process the user runs and cannot bound a sandbox
  **[observed in the local manual]**. macOS relies on tree polling plus the timeout. Linux can use
  `pids.max` via cgroups.
* **Disk:** per-file `RLIMIT_FSIZE`, a polled cap on total bytes written in the copy, and output
  capture caps. No filesystem quota on macOS. Residual: a fast writer can still fill the disk before
  the poll fires.
* **Output:** a shared byte cap across both streams with kill on overflow (existing `run_bounded`
  behavior).

The distinction the design makes explicit: **confidentiality and integrity boundaries (network,
out-of-copy writes, credential reads) are hard requirements enforced by a proven sandbox; availability
limits are best effort and reported per resource as `enforced`, `best_effort` or `none`.** A run on
macOS therefore may degrade the user's machine for a while; it cannot silently exfiltrate or modify.

### 4.3 Network

**A13. Network exfiltration, DNS and covert egress.** The test posts `~/.ssh` contents (if it
managed to read them) to a server, or encodes them in DNS lookups.
Mitigation: deny all network operations at the kernel policy level; the proxy variables Polaris sets
are defence in depth only, not enforcement (as the comment in `controlled_environment` says).
**[observed]** On macOS `(deny network*)` turned a loopback TCP connect to a live listener from
success into `Operation not permitted`, and a closed-port connect from `Connection refused` into
`Operation not permitted` (experiments N1 and N2, so the denial is the sandbox and not a missing server);
`bind`/`listen` was also denied. **DNS is [unverified]**: my lookup test used a name that fails to
resolve with or without a sandbox, so it proves nothing. On macOS the system resolver is a Mach
service that performs the query on the process's behalf, so a policy that denies sockets but allows
that Mach lookup might leak query names. Hence the deny-by-default `mach-lookup` policy in A9 and an
explicit adversarial test with a local UDP listener. On Linux, `--unshare-net` leaves only a loopback
device in a separate namespace (bubblewrap README [documented]). Residual: unresolved items above.

**A14. Loopback and local services.** Databases, Docker daemons, local model servers (for example on
port 11434), dev servers, IDE and agent sockets, `ssh-agent`.
Mitigation: TCP to loopback is denied by the macOS policy **[observed]**, and in a separate Linux
network namespace the host's loopback services are unreachable **[documented]** (the sandbox has its
own loopback). Filesystem Unix sockets: reachable only if the path is visible or connect is allowed
by policy. **My Unix-socket experiment was inconclusive** (the baseline connect also failed), so
Unix-socket denial on macOS is **[unverified]**; the policy must deny `network-outbound` including
Unix sockets, and the original worktree, `$HOME` and `/var/run` are unreadable, so well-known socket
paths are not visible. Residual: tests that need a local database cannot run in v1; the result will say
`failed` and the user must use their own environment.

### 4.4 Git, packages and timing

**A15. Git hooks and git configuration.** A repository can carry hooks and configuration that make a
*Git command* run code. githooks(5) documents hooks and `core.hooksPath` **[documented]**; git-config
documents configuration keys that name commands. Merely listing tracked files with Git on a hostile
repository could execute attacker-chosen programs outside the sandbox.
Mitigation: the copy is not a Git repository (`.git` is never copied). Polaris's `offline_environment`
already neutralizes global and system config; **repository-local** config is the remaining surface,
so the runner (a) lists tracked files by invoking Git only with a controlled environment, explicit
`-c` overrides of known command-running keys, and under the same no-network, no-write sandbox, and
(b) refuses to run if repository-local config contains command-running keys. The exact list of keys to
override and refuse must be taken from the git-config manual at implementation time **[I fetched the
manual but the page was truncated before the relevant section; not verified here]**. Residual: a Git
bug or an unknown key. Tests that call `git` inside the copy see no repository and fail; that is
disclosed.

**A16. Package install scripts and lifecycle scripts.** `postinstall`, `setup.py`, build backends.
Mitigation: the runner never installs anything and has no network, so installs inside the run fail.
Lifecycle scripts that run as part of the test command itself (for example `pretest` and `posttest`
when the user runs `npm test`) run inside the sandbox. npm documents that `ignore-scripts` exists as a
config setting **[documented]**, but Polaris does not add flags to the user's command. Residual:
whatever install scripts did **before** the run (when the user created `.venv` or `node_modules`) is
outside this threat model and outside this sandbox.

**A17. Time of check to time of use.** The worktree changes between snapshot and run, or the copy
changes between self-test and run, or the sandbox backend binary is replaced.
Mitigation: (a) the copy is built once into a private `0700` directory with no-follow I/O and a tree
digest is computed from the **copy** immediately before launch and recorded; later changes to the
user's worktree cannot affect the run and are detected at apply time by the existing snapshot digest
checks; (b) the self-test and the real run use the same launcher, the same profile bytes (digest
recorded) and a freshly hashed backend binary; (c) backend executables are absolute, fixed paths (as
`process.py` does), never `PATH`, cwd or repository lookups; (d) the test may change the copy while it
runs, which is expected; the recorded digest is of the pre-run tree, so it cannot be altered from
inside. Residual: a same-uid attacker is out of scope (3.3).

### 4.5 Output and results

**A18. Output as a terminal injection vector.** Escape sequences in test output can change the
terminal, rewrite what the user sees, or, depending on the terminal, trigger side effects. The
Wasmtime security documentation says plainly that untrusted output with escape sequences "can have
side effects including writing to files, executing commands, injecting text into the stream as if
the user had typed it, or reading the output of previous commands" and that Wasmtime therefore filters
terminal writes into inert replacement sequences **[documented]**.
Mitigation: the sandboxed process gets pipes, never a terminal. Polaris never writes raw child bytes
to a terminal. Before display, all C0 and C1 control characters except newline and tab, all escape
sequences (CSI, OSC including OSC 8 hyperlinks and OSC 52 clipboard, DCS) and Unicode bidirectional
and invisible formatting characters are replaced with visible, inert escapes; lines are length-capped;
output is shown inside a labelled "untrusted output from your test command" frame. JSON output is
escaped and bounded. This reuses the rule `process.py` already states: raw child output is never copied
into user-visible errors. Residual: terminal emulators with parsing bugs on printable bytes.

**A19. Output as an injection vector into an AI.** Test output is attacker-controlled text.
Mitigation for v1: it is never sent to any model. Only an exit status, a sanitized tail for display, and
digests exist. Any future design that returns failures to an AI (B4) must treat output as data, pass
only structured, validated fields, and carry its own review.

**A20. Results spoofing.** The test prints `tests: passed`, forges a `polaris-result` line, or exits
0 with no tests collected.
Mitigation: the status is derived **only** from the exit status of the child that Polaris started and
from limits Polaris itself enforced. Output is never parsed for pass or fail. A launch handshake from
Polaris's own launcher proves the command started, so a sandbox setup error cannot be mistaken for a
test failure. Residual, stated plainly: the hostile code can exit 0, and a suite that collects zero
tests can exit 0. A baseline run (the unmodified snapshot) is recorded to expose some of this: a
suite that "passes" both with and without the change is evidence about the suite as much as the
change.

**A21. Weakening the tests to make them pass.** A proposal that touches test files, test
configuration, CI files, lockfiles or package scripts changes what "passed" means.
Mitigation: the existing scope gate limits edits to files tied to the finding. In addition the result
carries `changed_test_or_config: true` and the label becomes "passed, tests or test configuration were
modified by this change" when the proposal touches such paths. Residual: classification of "test file"
is heuristic by path.

**A22. Confirmation spoofing.** A long, Unicode-confusable or control-character-laden command line
hides what will run.
Mitigation: the command is parsed into an argument vector (no shell interpretation by Polaris), shown
in full with every control character escaped, with the working directory inside the copy, the
read-only mounts, the environment names and values, the limits, the backend and the platform. Control
characters in the argument vector are refused. Residual: a command whose own semantics are obscure
(for example `make test`, which runs recipes from the repository) is still untrusted code, which the
confirmation says.

**A23. Residue and cross-run contamination.** Copies left on disk; shared caches carrying state between
runs.
Mitigation: a fresh copy and a fresh private `HOME` per run, no shared caches, deletion after the run
(not secure erasure) and a sweep of stale Polaris-owned run folders at the start of the next run. Copies
hold repository source, so the folder is `0700` and the privacy limitation is documented.

**A24. Privilege.** The runner running as root, or with a setuid helper.
Mitigation: refuse to run as uid 0; refuse any backend that needs privilege escalation; bubblewrap
without setuid is the only Linux namespace backend considered, consistent with its README's statement
that the setuid mode was removed **[documented]**.

## 5. Mechanisms evaluated

For each: isolation strength, network denial, resource limits, availability, setup burden, how it fails,
and how Polaris would detect that it is enforcing. The self-test is common to all and described in 5.7.

### 5.1 macOS `sandbox-exec` / Seatbelt

What it is: the kernel mandatory-access-control sandbox applied by `/usr/bin/sandbox-exec -p <profile>
command`. The profile language (SBPL) is a Scheme-like dialect.

Facts:

* The manual page on this machine (dated March 9, 2017) says: "The sandbox-exec command is
  DEPRECATED. Developers who wish to sandbox an app should instead adopt the App Sandbox feature"
  **[observed]**. The binary on this machine is `/usr/bin/sandbox-exec`, 102,368 bytes, dated Jul 10.
  No deprecation warning appeared in any of my runs, though a third-party report on a different macOS
  version shows one on stderr **[unverified]**. Apple publishes no replacement for sandboxing arbitrary
  command-line processes: the same report says App Sandbox needs a signed app bundle and entitlements
  **[unverified: GitHub issue, not Apple documentation]**. The SBPL language is not formally documented
  by Apple; the best references are Apple's own profiles under `/System/Library/Sandbox/Profiles` and
  reverse-engineered write-ups **[unverified]**. A 2011 paper by Blazakis describes the architecture
  (Seatbelt as a TrustedBSD MAC policy module, profiles compiled from Scheme and passed to the kernel);
  I read it through a third-party mirror and it is old, so treat it as background **[unverified]**.
* Enforcement is in the kernel and is inherited by children. **[observed]** A child `/bin/sh` inside the
  sandbox could not write outside (experiment 7), and a sandboxed process could not apply a looser
  profile (experiment 15: `sandbox_apply: Operation not permitted`).
* What profiles **can** deny **[observed]**: all network (`network*`), including loopback TCP connect and
  listen (experiments N2, N4, N5); writes outside a named directory; reads of a named folder
  (experiment 11); and with `(deny default)` and no allowances, even `exec` (experiment 12).
* What they **cannot** do: they do not bound memory, process count or disk; they have no PID namespace;
  they do not hide other processes' existence; and their strength depends entirely on the operations
  the profile leaves allowed. An allow-default profile such as the Semgrep one leaves reads, Mach
  lookups, signals and process-info open **[observed for reads; others unverified]**.
* Profile pitfalls found: paths must be the resolved path, or the allow silently fails to match
  (experiment 5); `/tmp` is a symlink to `/private/tmp` on macOS. Rules are order-sensitive: a
  later allow overrides an earlier deny **[observed for writes, experiment 2; assumed identical for
  reads, to be tested]**.
* Profile size: a third-party document gives a 65,535-byte serialized limit **[unverified]**.

Isolation strength: kernel-enforced and inherited, but the policy is hand-written against an
undocumented language and a very large Mach and system surface. Strength is "only as good as the
deny-by-default profile and its review".

Network denial: yes for sockets **[observed]**; DNS via the system resolver **[unverified]**.

Resource limits: `setrlimit` CPU, file size, open files and core size only (A12). Memory and processes
are not bounded by this mechanism.

Availability: any macOS with `/usr/bin/sandbox-exec`; today's code already assumes it
(`sandbox_available()` only checks that the file exists, which is **not** proof that it enforces).

Setup burden: none for the user; large for Polaris (profile engineering, per-OS-release qualification).

How it fails: the profile is too narrow and the toolchain fails to start (visible, fails safe); the
profile is wrong in a permissive direction (invisible, dangerous); a future macOS removes or changes the
tool or an operation name (the profile fails to compile, which fails safe); a kernel or sandbox bug
allows escape (not detectable by Polaris).

How Polaris detects enforcement: the self-test in 5.7, run on every invocation, plus an allowlist of
macOS versions with recorded qualification evidence, as the existing analyzers already do for the
Semgrep graph. Unknown macOS versions are refused.

### 5.2 Linux user namespaces: bubblewrap, `unshare`, Landlock

What it is: unprivileged user, mount, PID and network namespaces. The kernel manual says user
namespaces give "full privileges for operations inside the user namespace, but ... unprivileged for
operations outside" **[documented]**. Bubblewrap builds a sandbox from them.

Facts from the bubblewrap README **[documented]**: it creates a new, empty mount namespace whose root is
a tmpfs, and you add only what you choose; PID namespaces hide outside processes; a network namespace
"will not see the network. Instead it will have its own network namespace with only a loopback device";
it sets `PR_SET_NO_NEW_PRIVS`; it is **"not a complete, ready-made sandbox with a specific security
policy"**, so protection "is entirely determined by the arguments passed"; with `TIOCSTI` unfiltered,
`--new-session` is needed (CVE-2017-5226); anything bound in, such as a D-Bus socket, can be used to
escape; and the setuid mode has been removed so it needs unprivileged user namespaces.

Unprivileged user namespaces are also a kernel attack surface: Ubuntu's 2023 article reports that
44% of the exploits Google observed needed them, and describes restricting them per application with
AppArmor **[documented]**. On such systems the runner's `bwrap` may be refused, which is a platform
availability issue, not an error to work around.

`unshare` alone gives namespaces but no filesystem assembly; bubblewrap is the practical choice.
Landlock is an unprivileged kernel access-control API; its documentation lists filesystem and network
(TCP, and UDP in newer ABIs) rights and says a ruleset restricts the thread and its future children
**[documented]**. It needs a recent kernel and a launcher that applies it before `exec`. It is a
reasonable defence-in-depth layer inside bubblewrap on Linux; I do not recommend it as the only layer in
v1. ABI availability per kernel **[unverified]**.

Isolation strength: good for filesystem, network, PID, with a deny-by-default mount layout (so
`~/.ssh` is simply not there). Shares the host kernel, so a kernel bug is an escape.

Network denial: new network namespace.

Resource limits: none of its own. Use cgroup v2 (`systemd-run --user` scope or a delegated cgroup) and
`prlimit`, availability **[unverified]** per host; otherwise report `none` for that resource.

Availability: Linux with `bwrap` installed and unprivileged user namespaces enabled. The existing
`sandbox_available()` looks for `/usr/bin/bwrap` or `/bin/bwrap` only.

Setup burden: install bubblewrap; enable user namespaces on hardened distributions.

How it fails: `bwrap` cannot create the namespace (fails safe, run refused); too-permissive bind
mounts (dangerous: the existing `--ro-bind / /` is exactly this); inside containers or CI where
namespaces are unavailable.

Detection: the self-test, plus verifying the namespace actually exists (the probe checks that it is
PID 1 or that `/proc` shows only its own processes).

### 5.3 Rootless containers the user already has (podman, Docker)

* Docker's documentation says the daemon "always runs as the `root` user" by default and that
  membership of the `docker` group "grants root-level privileges to the user" **[documented]**. A
  Polaris runner must **never** use a rootful Docker daemon: handing project code to a root-equivalent
  service widens the blast radius.
* Rootless mode runs "the Docker daemon and containers inside a user namespace" and needs `newuidmap`,
  `newgidmap` and subordinate UID ranges **[documented]**. Podman's `run` manual documents capability
  controls and warns that capabilities such as `CAP_SYS_ADMIN` are "particularly dangerous when they are
  not used within a user namespace" **[documented]**. Options for networks, read-only roots and
  pid/memory limits exist in podman and Docker run references; I did not re-read each one **[unverified
  here]**.
* On macOS, containers run in a Linux VM provided by the engine; a container backend there is a
  VM-isolated option. The Docker CLI on this machine is version 29.8.0 and its daemon was not running
  **[observed]**; I did not start it or test any container.

Isolation strength: namespaces plus a container runtime plus (on macOS) a VM; strongest when rootless
and with networking disabled and a read-only root.

Network denial: `--network none` style options **[unverified here]**; the self-test decides.

Resource limits: the best available story: cgroups for memory, pids and CPU **[documented that cgroup
options exist, `--cgroup-conf`; per-option not re-read]**.

Availability: only if the user already has an engine and an image that contains their toolchain. The
runner must not pull images (that is network use and an untrusted artifact) and must not build one.

Setup burden: high and varied; the toolchain must exist in the image, the copy and dependencies must be
mounted, and file-sharing semantics differ on macOS.

How it fails: engine not running; rootful engine (refuse); image missing; mounts expose more than
intended (the mount list is the policy).

Detection: self-test inside the container; verify rootless and the absence of the Docker socket mount.

Verdict for v1: defer as a second backend. It is the right answer for users whose toolchain already
lives in a container, but it makes the first version depend on engine behavior I have not verified.

### 5.4 gVisor, Firecracker and microVMs (the strong option)

* **gVisor** interposes a user-space kernel (the Sentry) between the application and the host; its
  security-model page says the sandbox's own host interactions are limited to a small set of
  operations that do not include creating new sockets unless host networking is enabled, and that it
  relies on host cgroups for resource exhaustion **[documented]**. It
  protects against kernel bugs reachable from the System API, not against hardware side channels. It is
  Linux-only, normally used through a container runtime, and has non-trivial compatibility gaps for
  arbitrary toolchains **[unverified]**.
* **Firecracker** is a virtual machine monitor on Linux/KVM. Its design document says "all vCPU threads
  are considered to be running malicious code as soon as they have been started", recommends the
  `jailer`, and states that it "does not perform any network traffic filtering", so egress control is
  the host's job **[documented]**. It needs `/dev/kvm`, a guest kernel and rootfs, and host networking
  plumbing the user does not have by default.
* **Apple Containerization** runs each Linux container in its own lightweight VM on Apple silicon with
  Virtualization.framework; it requires macOS 26 and Xcode 26 to build, and its README (at version
  0.1.0) says source stability is only guaranteed within minor versions **[documented]**. The
  `container` command-line tool
  is a separate install. This is the credible macOS path to VM isolation, but it needs a Linux toolchain
  image and installing third-party software, which Polaris must not do.

Isolation strength: highest (a separate kernel). Network denial: no virtual NIC at all. Resource limits:
VM memory and vCPU caps are real limits. Availability: low for the average developer. Setup burden: high.
How they fail: missing KVM or virtualization entitlement, nested virtualization unavailable in CI, guest
image drift. Detection: self-test inside the guest; confirm no NIC.

Verdict: the right target for users who need strong isolation and for a later "strong mode"; not a
first version for the general developer. Recording `isolation: vm` in results would let the label
reflect it.

### 5.5 WebAssembly and WASI

WASI's filesystem follows a capability model ("applications can only access files and directories
they've been given access to") and the sandbox has no raw system calls **[documented, Wasmtime
security page]**. WASI 0.2 and the 0.3 preview are the current versions **[documented]**.

It does not fit this job: user test commands are native programs (`pytest`, `npm test`, `cargo test`),
dependencies include native extensions, and recompiling a project's toolchain to WebAssembly is not
something Polaris can ask of the user. Rejected for the runner. One idea is worth borrowing: Wasmtime's
filtering of terminal escape sequences (A18).

### 5.6 Comparison and choice

* macOS first version: Seatbelt with a deny-by-default profile, labelled experimental and deprecated,
  or **not supported**. VM-backed backends are the strong alternative (5.3, 5.4) but not first-version.
* Linux first version: bubblewrap with an empty-root mount layout, fresh PID and network namespaces,
  `--new-session`, `--die-with-parent`, and cgroup limits only where the host allows them.
* Everything else: refuse.

The results record names the backend so the label can say what was actually used.

### 5.7 The enforcement self-test (fail closed)

Before every run the runner builds the exact launcher command it will use (same profile bytes, same
backend, same environment construction) and runs a **Polaris-authored probe**, not project code, inside
it. The probe is a small program run with Python's isolated flags like the existing launcher. The self-test
passes only if all of these hold:

1. **Positive controls.** The probe writes a file inside the copy, reads an allowlisted file and the
   same connection test succeeds when run *without* the sandbox against a Polaris-owned listener.
   Without positive controls a probe that fails for an unrelated reason would be mistaken for
   enforcement. I found this matters: a closed-port connect fails with "Connection refused" unsandboxed
   and with "Operation not permitted" sandboxed **[observed]**, so the probe must check the specific
   error, not just failure.
2. **Write denial.** Writing to a canary path outside the copy (inside a Polaris-created private folder)
   fails with a permission error and the canary is unchanged.
3. **Read denial.** Reading a planted canary file outside the allowlist fails with a permission error.
   The canary stands in for credentials; the real `~/.ssh` is never touched.
4. **Network denial.** Connecting to a Polaris-owned listener on an ephemeral loopback port fails with a
   permission error and the listener records zero connections; binding a socket fails. A UDP datagram to
   a Polaris-owned loopback listener is not delivered.
5. **Signal denial.** Signalling a sibling process Polaris started outside the sandbox fails.
6. **Namespace and limit facts** (Linux): the probe is alone in its PID namespace; stated limits are
   readable back.

If the backend is missing, the platform is not on the qualified list, any probe cannot run, or any check
fails, the result is `not_run` with a fixed reason code and **nothing else runs**. There is no override
flag in the first version. The self-test proves enforcement of the *probed operations*; it does not
prove the absence of escapes through other operations (A9). That is the adversarial suite's job and the
external review's.

## 6. Minimal design

### 6.1 The opt-in flow

* Entry point: `polaris fix --run-tests "<command>"` (name provisional) on an interactive terminal.
  The user types the command; Polaris never offers one.
* It is refused, with a fixed reason, when: running in CI (the existing `in_ci` check in
  `src/polaris/refactor/aiconfig.py` and `CI` variables), standard input or output is not a terminal,
  the process is invoked by the API server, the MCP server, an editor integration or an agent hook, the
  platform is unqualified, the user is root, a pull request from a fork is being processed, or the
  command text came from anywhere but the user's own terminal.
* No file in the repository can enable the runner, name or change the command, or add mounts.
  A repository must not be able to turn it on, just as it cannot turn AI on today.
* Before anything runs, Polaris shows one confirmation screen: the full argument vector with control
  characters escaped; "this will run code from this repository and its dependencies, including any
  AI-written change shown above"; the proposal diff summary; the read-only mounts; the environment;
  the limits and which are enforced; the backend and platform; and that the network is off. The user
  confirms with an explicit keystroke on the terminal. A persistent "always allow" does not exist.
* The user's worktree is not modified by the run. The proposal is applied to the **copy** only. Applying
  to the worktree stays the existing approval step.

### 6.2 What is copied

* A **tracked-files snapshot**: the files `git ls-files` lists (obtained safely, A15), regular files
  only, read from the working tree through the no-follow reader, so the user's uncommitted edits to
  tracked files are included and shown as such. Untracked files are not copied.
* Files whose names the existing scope rules call sensitive (`.env*`, `*.pem`, `*.key`, keys, credential
  files, `.git`, and similar) are **not** copied. Some tests need such fixtures; those tests will fail,
  and the result lists the omitted paths.
* The files the proposal changes are written into the copy afterwards from the proposal's exact bytes
  (digest-checked), never from a patch parser.
* Limits (proposed initial values, **not measured on any real repository**): 10,000 files and 100 MiB.
  Over the limit the runner refuses with `snapshot_too_large`. These numbers must be tuned from the
  spike.
* **Dependencies** (`.venv`, `node_modules`) are not copied. Tests need them, and installing is
  forbidden. The runner may mount, **read-only**, directories the user names explicitly (and the fixed
  names `.venv`, `venv`, `node_modules` if they exist in the repository root), subject to: absolute
  real path inside the repository root or an explicitly named toolchain directory, no symlinked
  components, not under a hard-refused credential location, size cap. Mounts are shown on the
  confirmation screen. They are untrusted code that is readable and executable but not writable.
  Consequence: the dependency directory sits at the original path, so the original worktree root cannot
  be wholly denied; the policy denies it **except** these named subpaths.
* The copy lives in a fresh `0700` folder with its private `HOME`, `TMPDIR` and cache folders inside it.

### 6.3 Execution

* The command is split into an argument vector with a shell-style splitter, **no shell is invoked** by
  Polaris, and the executable is resolved inside the sandbox against a minimal `PATH` plus the mounted
  directories. The resolved path is recorded in the result.
* Order: self-test; baseline run on a copy of the unmodified snapshot; run on a second fresh copy with the
  proposal applied. Two runs double the cost; the baseline is what separates "this change broke tests"
  from "the suite was already failing". The roadmap's value depends on that distinction.
* One run at a time. Wall-clock limit (proposed default 120 seconds, maximum 900), output cap (proposed
  1 MiB total across streams), kill the whole tree on any limit.
* The launcher is Polaris-owned and prints a start handshake on a private pipe before `exec`, so a
  sandbox set-up failure is `not_run`, never `failed`.

### 6.4 The result record

A new source-free record, provisionally `polaris.test-run/0.1.0`:

* `proposal_set_digest` (the digests of the proposals applied together), `snapshot_digest` of the copy
  tree before launch (baseline and changed), `command_digest` (the argument vector), `environment_digest`,
  `limits`, `backend` (identity: tool name, version, file digest, OS version), `profile_digest`, and
  `self_test_digest`.
* `baseline`: `passed | failed | not_run`; `after`: `passed | failed | not_run`; `reason` codes; exit
  statuses; elapsed time; which limit fired; `limit_enforcement` per resource
  (`enforced | best_effort | none`); omitted-path counts; `changed_test_or_config`.
* Output digests and truncation flags. Sanitized output is **not** in the record by default (it can contain
  secrets that were in tracked files); a bounded display tail is shown to the user and not persisted.
* It states what it is: *an observation made by this installation on this machine*. It is a digest-bound
  record, not a signature and not independently trusted CI evidence, matching how
  [engineering.md](../engineering.md) already describes digests.

Binding to the existing contracts:

* `VerificationRecord` currently has `behavioral_tests: Literal["not_run"]`, a fixed
  `behavioral_reason`, and `behavior_proven: Literal[False]`. This requires a **new format version**
  (`polaris.verification/0.2.0`); the old one must keep parsing. `behavior_proven` stays `False`.
* `FixPlan.behavioral_tests` is `Literal["not_run"]` today and will become the overall `tests` field with
  a mandatory reason.
* `ProposalApproval` gains an optional `test_run_digest` so a person's approval can cover the exact
  evidence they saw. `apply_proposal` refuses to treat evidence as current when the digest of the worktree
  state it applies to differs from the tested snapshot; the label becomes `tests: stale`.
* Decision recorded: one test run covers the **set** of proposals the user is about to apply, not one run
  per proposal.
* Mapping: exit 0 within limits is `passed`. Non-zero exit, timeout, output limit or resource kill is
  `failed` with a reason code (never `passed`; a four-state variant with `inconclusive` is an open
  question, section 9). `not_run` is for every case where the command did not start under a proven
  sandbox.

### 6.5 Output handling

Output is read from pipes, byte-capped, decoded as UTF-8 with replacement, then sanitized (A18). Neither
raw nor sanitized output is parsed for results, persisted in the record, sent to a model, or written
into SARIF, plans or proposals.

### 6.6 How results are labelled in `polaris fix`

Plain words, always with the level and what it does not mean. Examples, wording provisional:

```text
tests: passed       Your command `pytest -q` exited 0 in an isolated copy (network off,
                    backend: seatbelt, deprecated API). Baseline also passed. This is evidence,
                    not proof the change is correct. Level reached: L2.
tests: failed       Your command exited 1 with the change. Baseline passed, so the change
                    may have caused this.
tests: failed       Your command exited 1, and the baseline also failed. Not caused by the change
                    as far as this run can tell.
tests: not_run      The sandbox could not be proven to deny network access on this machine.
                    Nothing was executed. Level reached: L0.
```

Reasons are fixed codes (`runner_not_requested`, `sandbox_not_proven`, `unsupported_platform`,
`ci_refused`, `not_interactive`, `snapshot_unsupported`, `snapshot_too_large`,
`editable_install_points_outside_copy`, `command_not_started`, `limit_exceeded:<kind>`, and so on).
The level shown is L2 only when the result is `passed` or `failed` from a proven run; otherwise the
static level stands.

## 7. Platforms, tests, review, rollout, kill switch

### 7.1 Supported platforms for the first version, and refusals

Supported for an *experimental* build, each only when the self-test passes and the exact OS version is on
a qualified list with recorded evidence:

* macOS on Apple silicon, Seatbelt backend with the deny-by-default profile. Subject to the spike
  (condition C1). If the spike cannot run common toolchains without readable-everything, macOS is not
  supported in v1.
* Linux (x86-64 and arm64) with `bwrap` at a fixed absolute path, unprivileged user namespaces available,
  and a kernel for which the self-test passes.

Refused: Windows and WSL1; any platform without a passing self-test; any environment inside a container
without namespace support; root; macOS or Linux versions without recorded qualification; rootful Docker;
setuid helpers; any backend found on `PATH` rather than at a fixed path. Container and VM backends
(5.3, 5.4) are deferred, not forbidden.

### 7.2 Test plan

Unit tests cover parsing the command, environment construction, limit selection, sanitizer, record
validation and the refusal matrix (every refusal reason has a test, including CI variables, non-TTY,
MCP/API entry points and a command supplied by repository configuration).

**Adversarial tests.** These run **Polaris-authored probe commands** through the real runner on a
qualified platform and **must be denied**. Each asserts the denial and the absence of the effect.

* Writes: `../` and absolute-path writes; through a symlink planted by the test; to `/tmp`; to a path
  that exists in the user's real worktree stand-in; creating a launch agent or shell startup file in a
  stand-in home; hard-link creation to an outside file.
* Reads: a canary under a stand-in `~/.ssh`, `~/.aws`, and `.git/config` of the original worktree
  stand-in; another user's world-readable stand-in file; the original worktree root.
* Environment: a canary variable and a stand-in `SSH_AUTH_SOCK` set in the parent are absent in the
  child.
* Network: TCP connect to an ephemeral loopback listener (zero connections recorded); UDP datagram to a
  loopback listener; DNS lookup against a loopback resolver stand-in (zero queries); Unix-domain socket
  connect to a Polaris-owned socket; raw and system sockets; bind and listen.
* IPC and system services (macOS): `open`, `osascript` Apple Events, `launchctl` job submission,
  pasteboard access, process-info and `sysctl` reads of another process's environment; each must be
  denied.
* Processes: signals to a sibling process; `ptrace` and task-port attempts; fork bomb in a bounded
  variant (assert the runner terminates, kills the tree, and leaves no survivors in the standard case);
  `setsid` plus background process (survivor count is asserted, and the macOS residual in A11 is
  recorded, not hidden); memory hog (assert the kill or record `none`); disk fill past the cap; output
  flood past the cap; infinite loop past the timeout.
* Output: escape sequences, OSC 52, OSC 8, bidi controls and 10 MB of noise are sanitized or bounded;
  a command that prints `tests: passed` and exits 1 yields `failed`; a command that exits 0 with no
  output yields `passed` with the documented caveat.
* Snapshot: a worktree swapped for a symlink during the copy is refused; changes to the worktree after
  the snapshot do not change the recorded digest; a repository with a command-running Git hook or
  config key does **not** execute it during snapshot (a canary file stays absent).
* Self-test: a deliberately weakened profile (allow network, or allow-default reads) must make the
  self-test fail and the runner refuse. **A self-test that cannot fail is not a self-test.**
* Fuzz the sanitizer and the command parser.

Policy decision needed: today's project rule is that source in test fixtures is data that is parsed,
never executed. The adversarial tests execute Polaris-authored probe programs. They should live in a
clearly marked group, run only on a qualified platform, and be skipped elsewhere. This is an exception to
a stated rule and needs the owner's sign-off (section 9).

Measurements the spike must produce, with numbers, before any claim: time to run a baseline plus changed
run on three real repositories against the same unsandboxed command; failure rate of toolchains under the
deny-by-default policy; self-test duration; false `not_run` rate.

### 7.3 External review plan

1. **Design review** of this document by at least one reviewer with macOS Seatbelt experience and one with
   Linux sandbox experience, before the spike's code is written. Output: a written list of attack classes
   missing here, and the answers to section 9's questions on A8, A9 and A13.
2. **Implementation review**: after the spike produces the profile, launcher and self-test, give the
   reviewers the code, the adversarial suite and a throwaway virtual machine image to attack. Time-boxed;
   they are encouraged to break the self-test rather than the sandbox.
3. **Findings** are fixed or the platform is dropped. Findings and outcomes are summarized publicly in the
   changelog without exploit detail until fixed.
4. No public beta until no critical or high finding is open. I have not chosen reviewers or a budget; those
   are the owner's.

### 7.4 Staged rollout

* **Stage 0:** this design reviewed (no code).
* **Stage 1: spike**, not a product: the deny-by-default macOS profile and Linux bubblewrap layout, the
  self-test, and the measurements in 7.2. Kill criteria: the policy cannot run the target toolchains
  without readable-everything, or the self-test cannot fail closed, or an escape is found that cannot be
  closed.
* **Stage 2: internal experimental**: behind an undocumented environment variable, default off,
  maintainers only.
* **Stage 3: external review** of the implementation, fixes.
* **Stage 4: public opt-in beta**: documented flag, labelled experimental, qualified platforms only,
  prominent limitations.
* **Stage 5: general availability** only after the beta period without an escape report, a second review
  of changes since the first, and the owner's decision. The roadmap's B3 estimate (8 to 10 weeks) is
  sizing for the build; the review and beta periods are additional and not estimated here.

### 7.5 Kill switch

* Default off, and no persistent enable: enabling is typing the command on each invocation.
* `POLARIS_DISABLE_RUNNER=1` (provisional name) disables the runner everywhere, always honored, including
  by the experimental variable.
* The runner lives in one package behind one gate, so a patch release can disable it by changing a single
  constant without touching other features.
* A security release, a yanked wheel and a changelog notice are the only remote levers. **There is no
  remote kill switch, and none can exist, because Polaris does not phone home.** An installed version
  keeps whatever behavior it shipped with until upgraded; this is a real limit on how fast a mistake
  can be undone, and one reason to ship slowly.
* Any confirmed escape on a platform: that platform is removed from the qualified list in a patch release
  and the runner returns `not_run: platform_withdrawn`.

## 8. Recommendation

### 8.1 Verdict

**GO-WITH-CONDITIONS** for building an experimental first version. **NO-GO** for shipping any runner,
on any platform, that is only protected by the existing Semgrep-style profile or that cannot prove
enforcement before every run.

### 8.2 Conditions

* **C1. Spike with kill criteria** (7.4): a deny-by-default policy that actually runs the user's own
  `pytest` and `npm test` on real repositories. If it cannot on macOS, macOS is `not_run`, not weaker.
* **C2. Fail-closed self-test with positive controls** (5.7) that provably fails when the profile is
  weakened. No override flag.
* **C3. Adversarial suite** (7.2) green on each qualified platform, including the macOS Mach, DNS and
  process-info cases that are currently **[unverified]**, run in CI on those platforms.
* **C4. Independent external review** of design and implementation (7.3) with no open critical or high
  finding before any public beta.
* **C5. Entry restrictions**: CLI only, interactive TTY, never CI, never fork pull requests, never API,
  MCP, hook or agent entry points, never a command from a model, repository or configuration, no
  persistent enable.
* **C6. Honest labelling** (6.6): backend named, per-resource enforcement disclosed, baseline shown,
  `behavior_proven` stays false, hostile-repository caveat stated in the docs.
* **C7. No network ever and no installation inside the sandbox** in this version.
* **C8. Owner accepts these residual risks** in writing: macOS uses a deprecated, undocumented API; macOS
  memory, process-count and disk limits are best effort; a hostile repository can fake a pass; orphan
  processes on macOS may outlive the run (still confined); there is no remote kill switch.
* **C9. Linux only with bubblewrap** at a fixed path and unprivileged user namespaces; container and VM
  backends are a later, separately reviewed addition. Rootful Docker is never used.

### 8.3 What the roadmap loses if the answer is no-go

Phase 1 and Phase 2 are untouched. A (architecture), B1 and B2 (more and bigger fixes), C1 (rule engine),
the benchmarks and provider validation do not depend on B3.

What is lost:

* The `tests:` evidence level. `polaris fix` keeps reporting `tests: not_run`, which is honest.
* B4's test-failure feedback. Verifier-in-the-loop AI repair still works with the verifier's rejection
  reasons, which is a smaller signal.
* C3, AI-driven refactoring. The roadmap already says that without tests Polaris refuses rather than offer
  an unproven rewrite. Deterministic refactors that can reach L1 (C2 in the roadmap) are unaffected.

A cheap fallback that keeps the principle intact: after the user applies a fix, they run their own tests
themselves, outside Polaris. Polaris records nothing about it and never claims it. A possible later
addition is reading a user-supplied test report and labelling it "reported by the user, not run by
Polaris"; that is not worth designing now.

## 9. Open questions

For the owner (decisions) and for the reviewer (technical):

1. **macOS backend.** Is an experimental Seatbelt backend acceptable at all, given the deprecation and the
   reliance on an undocumented language, or should macOS wait for a VM-backed backend (Apple
   Containerization or an engine the user has)? My view: try the spike, and drop macOS if the deny-by-default
   policy does not hold up.
2. **Four states?** Should timeouts and resource kills be `failed` with a reason (as drafted) or a fourth
   state `inconclusive`? The roadmap says three states.
3. **Test policy exception.** May the adversarial suite execute Polaris-authored probe programs despite the
   "fixtures are data, never executed" rule, in a marked group on qualified platforms?
4. **Review.** Who reviews, with what budget and timeline, and is a paid reviewer acceptable?
5. **One run per set of proposals** (drafted) or per proposal? The latter costs N times as much.
6. **Baseline always?** Running the unmodified baseline doubles the cost. I recommend always.
7. **Minimum platforms:** which macOS and Linux versions are qualification targets for the first version?
8. **Public beta timing** relative to Phase 3 in the roadmap, given review and beta time are not in the
   8 to 10 week estimate.
9. **Environment variables:** is a literal `NAME=value` flag acceptable, or should the first version allow
   no variables at all?
10. Technical, for the reviewer: can a confined macOS process cause an out-of-sandbox DNS query, launch a
    process through LaunchServices, `launchd` or Apple Events, or read another process's environment, under
    a deny-by-default profile with the allowlist described in A9? What is the minimal safe `mach-lookup` and
    `sysctl-read` allowlist for CPython and Node?

## 10. What was verified, and what was not

### 10.1 Verified by me on this machine ([observed], Appendix A)

* `/usr/bin/sandbox-exec` exists and works; its manual says DEPRECATED (page dated March 9, 2017).
* With `(allow default)(deny network*)(deny file-write*)` plus an allow for one resolved directory: writes
  inside succeed, writes outside are denied, writes through a symlink to the outside are denied, the child
  shell is equally confined, the file system remains readable.
* A profile built from an unresolved `/tmp` path fails to allow writes inside the directory.
* `(deny network*)` denies loopback TCP connects to a live listener, closed-port connects, and `bind`/`listen`;
  the error is `Operation not permitted` (distinguishable from `Connection refused`).
* A read denial on a folder works; `(deny default)` with nothing allowed prevents even `exec`; a deny-default
  profile with read, exec, fork, sysctl-read and Mach lookups allowed can run `/bin/echo`; adding no write
  allowance still denies writes.
* A sandboxed process cannot start a nested `sandbox-exec` with a looser profile.
* The local `setrlimit(2)` manual lists no address-space limit and describes `RLIMIT_NPROC` as per user id.
* No `bwrap`, `unshare`, `podman` or `runsc` on this machine. The Docker CLI is present, its daemon was not
  running.

### 10.2 Read in primary documents on 2026-10-06 ([documented])

* The bubblewrap README (mount, PID, network namespaces; no-new-privs; not a ready-made policy; `TIOCSTI`;
  bound-in sockets; setuid mode removed).
* user_namespaces(7) (privileges inside versus outside the namespace; unprivileged creation since Linux 3.8).
* Ubuntu's 2023 article on restricting unprivileged user namespaces (the exploit-chain statistic is Ubuntu's
  citation of a Google report, which I did not read).
* The Linux kernel Landlock documentation.
* The gVisor security model page; the Firecracker design document; the Docker rootless and `docker` group
  pages; the podman-run manual (partially read); the Apple Containerization README; the Wasmtime security
  page; the WASI README; githooks(5) (hooks and `core.hooksPath`); the npm config page (`ignore-scripts` is a
  config setting).

### 10.3 Not verified

* Everything in A8 to A10 and A13's DNS clause on macOS: process-info and `sysctl` reads of other
  processes, Mach services, LaunchServices, `launchd`, Apple Events, pasteboard and resolver leakage, signals.
* Unix-domain-socket denial on macOS (my experiment was inconclusive).
* That common toolchains (CPython, Node, Rust, Java) run under a deny-by-default read and Mach policy. I
  built no such profile.
* The fork-bomb, memory, disk and output limits on macOS: nothing was run.
* Any Linux behavior: no Linux host or bubblewrap was available. All Linux facts above are from
  documentation, not from running anything.
* Container engines: no container was run. Option names and defaults beyond what I read are unchecked.
* Whether `systemd-run --user` cgroup limits are available on typical developer machines.
* Whether newer macOS releases change `sandbox-exec` (the third-party report of a deprecation warning,
  the 65,535-byte profile limit, a Bazel/Nix/Claude Code/Codex usage claim, and "40 of 42 vectors blocked" are
  all third-party statements I did not check).
* The exact set of Git configuration keys that run commands (the git-config page I fetched was truncated).
* Landlock ABI availability per kernel version.
* All proposed numeric limits (files, bytes, timeout, output): they are guesses, not measurements.
* That any real repository's tests pass under the sandbox at all.

## Appendix A: experiments run for this document

Machine: macOS 26.6 (build 25G5065a), Apple silicon (arm64), Darwin kernel 25.6.0. `/usr/bin/sandbox-exec`
present. Only system utilities ran (`/bin/echo`, `/usr/bin/touch`, `/bin/cat`, `/bin/sh`, `/usr/bin/nc`)
against files in a fresh temporary directory and a loopback port; no repository code, no real credentials.
The scripts were throwaway and are not part of the repository; the profile is shown so the results can be
reproduced. Listeners were stopped and the temporary folders deleted afterward.

Profile P1 (the shape used today for Semgrep), `<ws>` being the resolved path of a temporary directory:

```text
(version 1)(allow default)(deny network*)(deny file-write*)
(allow file-write* (subpath "<ws>"))(allow file-write* (literal "/dev/null"))
```

The profiles named below are P1 above, `P2` (read denial), `P3` (`(version 1)(deny default)`) and `P4`
(`(version 1)(deny default)(allow process-exec*)(allow process-fork)(allow file-read*)(allow sysctl-read)
(allow mach-lookup)(allow signal (target self))`). `<outside>` is a sibling folder of `<ws>` that the profile
does not allow writing to. Observed, in the order the text cites them (exit code and message):

1. `/bin/echo hello` under P1: exit 0.
2. `touch <resolved ws>/in.txt` under P1: exit 0 (file created).
3. `touch <outside>/out.txt` under P1: exit 1, `Operation not permitted`.
4. `cat <outside>/canary.txt` under P1: exit 0, printed the canary (P1 does not deny reads).
5. Same as 2 with the profile built from the unresolved `/tmp/...` path: exit 1, `Operation not permitted`.
6. `sh -c 'echo x > <ws>/link.txt'`, where `link.txt` is a symlink to a path in `<outside>`, under P1: exit 1,
   `Operation not permitted`. Nothing was created in `<outside>`.
7. `sh -c 'echo x > <outside>/child.txt'` under P1: exit 1, `Operation not permitted`.
8. Inconclusive: `nc -z -w 2 127.0.0.1 9` printed nothing and exited 1 both unsandboxed and under P1.
9. Inconclusive: same as 8 under P1, so no information.
10. Inconclusive: `nc -z -w 2 example.invalid 80` fails to resolve with or without a sandbox, so it says nothing
    about DNS under a sandbox.
11. P2, which is `(version 1)(allow default)(deny file-read* (subpath <outside>))`, then
    `cat <outside>/canary.txt`: exit 1, `Operation not permitted`.
12. P3, then `/bin/echo hello`: exit 71, `sandbox-exec: execvp() of '/bin/echo' failed: Operation not
    permitted`.
13. P4, then `/bin/echo hello`: exit 0.
14. P4, then `touch <outside>/p4.txt`: exit 1, `Operation not permitted`.
15. P1, then a nested `sandbox-exec -p '(version 1)(allow default)' touch <outside>/nested.txt`: exit 71,
    `sandbox_apply: Operation not permitted`. No file was created.

Second run, a verbose loopback network probe (port 9 and one ephemeral port; no traffic left the machine):

* N1. Unsandboxed `nc -v -z -w 2 127.0.0.1 9`: `Connection refused`.
* N2. Under P1: `Operation not permitted`.
* N3. Unsandboxed connect to a live `nc -l 127.0.0.1 <port>` listener: `succeeded`.
* N4. Under P1, the same connect to a live listener: `Operation not permitted`.
* N5. Under P1, `nc -l -w 1 127.0.0.1 <port>` (bind and listen): `Operation not permitted`.
* N6. Unix-domain socket connect with `nc -U`: the unsandboxed baseline also failed with no message, so the
  sandboxed result is inconclusive and counts for nothing.

No deprecation banner appeared in any output of these runs.

Not run, and therefore not claimed: any DNS leak test, any Mach, `launchd`, Apple Event or pasteboard test, signals
to other processes, process-info or `sysctl` reads of other processes, resource-limit enforcement, a real
toolchain (pytest, node) under a deny-by-default profile, anything on Linux, any container, any timing.

## Appendix B: sources

All accessed 2026-10-06 unless a date is given.

* macOS `sandbox-exec(1)` and `setrlimit(2)` manual pages, read on the test machine.
* bubblewrap README: https://github.com/containers/bubblewrap/blob/main/README.md
* `user_namespaces(7)`: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
* Ubuntu, "Restricted unprivileged user namespaces are coming to Ubuntu 23.10" (9 October 2023):
  https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces
* Linux kernel Landlock documentation: https://docs.kernel.org/userspace-api/landlock.html
* Docker rootless mode: https://docs.docker.com/engine/security/rootless/
* Docker Linux post-installation steps (the `docker` group warning):
  https://docs.docker.com/engine/install/linux-postinstall/
* podman-run manual: https://docs.podman.io/en/latest/markdown/podman-run.1.html
* gVisor security model: https://gvisor.dev/docs/architecture_guide/security/
* Firecracker design: https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
* Apple Containerization: https://github.com/apple/containerization
* Wasmtime security: https://docs.wasmtime.dev/security.html
* WebAssembly System Interface: https://github.com/WebAssembly/WASI/blob/main/README.md
* githooks(5): https://git-scm.com/docs/githooks
* git-config(1): https://git-scm.com/docs/git-config
* npm configuration (`ignore-scripts`): https://docs.npmjs.com/cli/v10/using-npm/config#ignore-scripts
* Secondary and unverified: the discussion of `sandbox-exec` deprecation on apple/containerization issue 737
  (May 2026), https://github.com/apple/containerization/issues/737; D. Blazakis, "The Apple Sandbox"
  (January 2011); and community SBPL references. They are cited only where marked [unverified].

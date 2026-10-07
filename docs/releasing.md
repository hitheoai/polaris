# Releasing Polaris

How a Polaris release is built, signed and published, and how anyone can check that the files
they install came from this repository.

## What a release contains

- **The `theovex-polaris` Python package** on PyPI: a wheel and a source archive, built by
  `scripts/build_public_wheel.py --sdist`. PyPI stores a signed attestation of where each file
  came from (Trusted Publishing).
- **A GitHub release** with the same two files, a Sigstore bundle for each file
  (`*.sigstore.json`), GitHub build provenance and a `SHA256SUMS` file.
- **A Homebrew source formula**, published separately in
  [hitheoai/homebrew-tap](https://github.com/hitheoai/homebrew-tap), for Apple Silicon macOS.
  It uses the published source archive and includes the terminal UI and MCP integration,
  without Semgrep or local-model dependencies. No prebuilt Polaris bottle is published.

Not released yet: the macOS installer and the legacy managed-analyzer bundle. Their tooling
remains in this repository (`packaging/homebrew/`, `packaging/installer/` and the
`scripts/*release*` helpers). The blocked formula in `packaging/homebrew/` is not the public
source formula. Publishing the separate tap does not approve the managed bundle's licensing,
signing or acceptance requirements.

## How a release runs

The release workflow (`.github/workflows/release.yml`) never starts on its own, and a tag push
alone publishes nothing.

1. **Version.** Set `version` in `pyproject.toml` and `__version__` in
   `src/polaris/__init__.py`, and describe the changes in `CHANGELOG.md`. The workflow refuses a
   tag that doesn't match both.
2. **Tag.** Tag the reviewed commit `vX.Y.Z` and push the tag.
3. **Start it by hand** from that tag (Actions > Release > Run workflow), with
   *approve_publication* checked. It runs only in the repository named by the
   `PUBLIC_RELEASE_REPOSITORY` variable, and only from a `v*` tag.
4. **Build and check** (environment `release-approval`, which needs a maintainer's approval):
   lint, type checks and the full test suite, then the wheel and source archive are built. The
   wheel is installed in a clean environment and must flag a risky sample.
5. **Publish to PyPI** (environment `pypi`, which needs a second approval): the files are
   uploaded with Trusted Publishing. No API token exists anywhere.
6. **Sign**: build provenance, a Sigstore bundle per file and `SHA256SUMS` are attached to a
   *draft* GitHub release, which a maintainer reviews and then publishes.

Every action in the workflow is pinned to a full commit, and values reach shell scripts only
through environment variables, never by `${{ }}` interpolation.

## Updating the Homebrew tap

After publishing and verifying the Python release, update `Formula/polaris.rb` in
[hitheoai/homebrew-tap](https://github.com/hitheoai/homebrew-tap), not this repository's
legacy bundle template. Verify the source archive's provenance and SHA256, review the
dependency changes, and follow the tap's maintenance instructions. In particular, preserve
the documented upstream source archives for native grammars whose PyPI archives omit headers.

Submit a tap pull request and merge only after its required Apple Silicon macOS check passes.
That check covers style, online audit, source installation, CLI/native-parser/TUI/MCP tests,
dependency consistency, reinstall and uninstall. Homebrew supplies Python and selected native
dependencies; it is not a completely frozen toolchain. There is no automatic version bump,
bottle publication or merge.

Verify the public `brew install hitheoai/tap/polaris` route before announcing availability.
Tap and documentation changes do not rebuild, replace or retag already-published Python
release artifacts.

## One-time setup (maintainers)

- **PyPI:** add a trusted publisher for the project `theovex-polaris`: this repository's owner
  and name, workflow `release.yml`, environment `pypi`.
- **GitHub environments:** create `release-approval` and `pypi`, each with required reviewers,
  deployable only from tags matching `v*`. Add a ruleset that restricts who can create tags.
- **GitHub variable:** set `PUBLIC_RELEASE_REPOSITORY` to this repository (`owner/name`).

## Verifying a release

A valid signature, checked against the expected repository, workflow and tag, binds the files
to the build that produced them. It doesn't prove the code is safe. Replace `X.Y.Z` with the
version you're checking.

```sh
# The PyPI attestation (this CLI is experimental)
python -m pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/hitheoai/polaris \
  pypi:theovex_polaris-X.Y.Z-py3-none-any.whl

# The Sigstore bundle from the GitHub release
python -m pip install sigstore
python -m sigstore verify identity theovex_polaris-X.Y.Z-py3-none-any.whl \
  --bundle theovex_polaris-X.Y.Z-py3-none-any.whl.sigstore.json \
  --cert-identity https://github.com/hitheoai/polaris/.github/workflows/release.yml@refs/tags/vX.Y.Z \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# GitHub build provenance, and the checksums
gh attestation verify theovex_polaris-X.Y.Z-py3-none-any.whl --repo hitheoai/polaris
shasum -a 256 -c SHA256SUMS
```

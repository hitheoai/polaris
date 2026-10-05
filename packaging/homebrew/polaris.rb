# Non-installable source template. scripts/build_homebrew_formula.py renders a new
# formula with a real artifact URL/checksum only after inspecting the matching bundle.
# This is a first-party binary tap distribution, not a homebrew/core source formula.
# No bottle or cross-prefix relocatability is claimed. macOS policy still applies.
raise "Generate a pinned candidate with scripts/build_homebrew_formula.py first." # @@GENERATOR_GUARD@@

require "digest"
require "json"
require "shellwords"

class Polaris < Formula
  desc "Local static security review and bounded proposals for engineering agents"
  homepage "https://polaris.theovex.com"
  # @@ARTIFACT_DECLARATIONS@@
  license "Apache-2.0"

  depends_on :macos
  on_macos do
    depends_on macos: :sequoia
  end
  depends_on arch: :arm64

  deny_network_access!

  def install
    manifest_path = buildpath/"manifest.json"
    odie "The release manifest does not match this formula." unless
      Digest::SHA256.file(manifest_path).hexdigest == THEO_MANIFEST_SHA256
    manifest = JSON.parse(manifest_path.read)
    odie "The release identity does not match this formula." unless
      manifest.fetch("format") == "polaris.theo-bundle/1" &&
      manifest.fetch("id") == THEO_RELEASE &&
      manifest.fetch("version") == version.to_s &&
      manifest.fetch("platform") == "macos-arm64" &&
      manifest.fetch("minimumMacOS") == "15.0"

    # Only inspected runtime archive contents are staged here, never a pre-built venv.
    # Homebrew owns the keg; standalone installer ownership/PATH machinery is not used.
    libexec.install "python", "uv", "manifest.json", "provenance.json"
    pkgshare.install "source", "third-party-sources"
    if manifest.key?("compliance")
      pkgshare.install "compliance"
      libexec.install "signing-report.json"
    end
    scratch = buildpath/"assembly-home"
    scratch.mkpath
    scratch.chmod 0700
    (scratch/"tmp").mkpath
    (scratch/"tmp").chmod 0700
    clean_env = [
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
      "HOME=#{scratch}", "TMPDIR=#{scratch}/tmp", "LANG=C",
      "XDG_CONFIG_HOME=#{scratch}/config", "XDG_CACHE_HOME=#{scratch}/cache",
      "UV_CACHE_DIR=#{scratch}/uv-cache", "UV_PYTHON_DOWNLOADS=never",
      "UV_NO_CONFIG=1", "UV_OFFLINE=1", "UV_COMPILE_BYTECODE=0",
      "PIP_CONFIG_FILE=/dev/null", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
      "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0",
      "SEMGREP_SETTINGS_FILE=#{scratch}/semgrep-settings.yml",
    ]
    uv = libexec/"uv/uv"
    python = libexec/"python/bin/python3.11"
    %w[app analyzer].each do |component|
      environment = libexec/component
      system "/usr/bin/env", "-i", *clean_env, uv, "--no-config", "--offline", "venv",
             "--python", python, environment
      system "/usr/bin/env", "-i", *clean_env, uv, "--no-config", "--offline", "pip", "install",
             "--python", environment/"bin/python", "--no-index",
             "--find-links", buildpath/"wheelhouse"/component/"wheels",
             "--require-hashes", "--no-build", "--link-mode", "copy",
             "-r", buildpath/"wheelhouse"/component/"requirements.txt"
      system "/usr/bin/env", "-i", *clean_env, uv, "--no-config", "--offline", "pip", "check",
             "--python", environment/"bin/python"

      validation = <<~PYTHON
        import importlib.metadata as metadata
        import json
        import os
        import re
        import stat
        import sys
        from pathlib import Path

        manifest = json.loads(Path(sys.argv[1]).read_bytes())
        component = sys.argv[2]
        assert ".".join(map(str, sys.version_info[:3])) == manifest["runtimes"]["python"]["version"]
        assert sys.prefix != sys.base_prefix
        packages = list(metadata.distributions())
        observed = {re.sub(r"[-_.]+", "-", p.metadata["Name"]).lower(): p.version for p in packages}
        assert len(observed) == len(packages)
        assert observed == manifest["environments"][component]
        if component == "app":
            import mcp
            import tomlkit
            from polaris import __version__
            assert __version__ == manifest["version"]
            assert "semgrep" not in observed
            from polaris.review.analyzers.identity import validate_manifest
            validate_manifest(manifest)
        else:
            assert observed["semgrep"] == manifest["analyzerIdentity"]["distributionVersion"]
            assert observed["mcp"] == "1.29.0"
        lock = Path(sys.prefix) / ".lock"
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            assert info.st_size == 0 and info.st_nlink == 1
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
      PYTHON
      system "/usr/bin/env", "-i", *clean_env, environment/"bin/python", "-I", "-B", "-c",
             validation, libexec/"manifest.json", component
    end
    identity_check = <<~PYTHON
      import json
      import sys
      from pathlib import Path
      from polaris.review.analyzers.identity import installed_identity, validate_manifest
      from polaris.onboarding.sources import verify_installed_sources

      manifest = json.loads(Path(sys.argv[1]).read_bytes())
      validate_manifest(manifest)
      assert installed_identity(sys.argv[2]) == manifest["analyzerIdentity"]
      verify_installed_sources(Path(sys.argv[3]), manifest["thirdPartySources"])
    PYTHON
    system "/usr/bin/env", "-i", *clean_env, libexec/"app/bin/python", "-I", "-B", "-c",
           identity_check, libexec/"manifest.json", libexec/"analyzer/bin/semgrep", pkgshare/"third-party-sources"

    # Homebrew's build/test sandbox cannot safely nest the analyzer's sandbox-exec.
    # Package assembly is checked here; real analyzer acceptance is a separate step.
    (libexec/"install-receipt.json").write JSON.pretty_generate(
      "format" => "polaris.theo-install/2", "manager" => "homebrew", "status" => "installed",
      "release" => THEO_RELEASE, "version" => version.to_s, "platform" => "macos-arm64",
      "manifest_sha256" => THEO_MANIFEST_SHA256,
      "packageValidated" => true, "analyzerRuntime" => "not_checked"
    ) + "\n"
    bin.mkpath
    { "polaris" => "polaris", "theo" => "polaris.onboarding" }.each do |name, entrypoint|
      (bin/name).write <<~SH
        #!/bin/sh
        exec #{Shellwords.escape((libexec/"app/bin/python").to_s)} -I -B -m #{entrypoint} "$@"
      SH
      (bin/name).chmod 0755
    end
    %w[polaris theo].each do |name|
      system "/usr/bin/env", "-i", *clean_env, bin/name, "--version"
    end
  end

  def caveats
    <<~EOS
      Both polaris and theo are installed. No project, editor, shell profile or credentials were configured.
      Project connection remains an explicit `theo setup --local` operation.
      Analyzer runtime validation is separate: run `polaris workflow capabilities` outside brew.
      A passing brew test does not establish Semgrep sandbox or native-editor acceptance.
      After upgrading, explicitly rerun setup for any editor configuration pinned to the old keg.
      Use brew upgrade/reinstall/uninstall for this installation, not a standalone runtime installer.
      Uninstall removes Homebrew's keg and links, including edits made inside the keg; it retains
      project/editor configuration and user credentials. Disconnect/logout are separate explicit actions.
      This candidate does not establish publisher signing, notarization or public availability.
    EOS
  end

  test do
    polaris_command = Shellwords.escape((bin/"polaris").to_s)
    theo_command = Shellwords.escape((bin/"theo").to_s)
    assert_match version.to_s, shell_output("#{polaris_command} --version")
    assert_match version.to_s, shell_output("#{theo_command} --version")
    system libexec/"app/bin/python", "-I", "-B", "-c", "import mcp, tomlkit"
    receipt = JSON.parse((libexec/"install-receipt.json").read)
    assert_equal "homebrew", receipt.fetch("manager")
    assert_equal true, receipt.fetch("packageValidated")
    assert_equal "not_checked", receipt.fetch("analyzerRuntime")
    (testpath/"app.py").write <<~PYTHON
      import os


      def ping(host):
          os.system("ping -c 1 " + host)
    PYTHON
    risky = JSON.parse(shell_output(
      "#{polaris_command} scan app.py --root #{Shellwords.escape(testpath.to_s)} " \
      "--engine rules --model-source local --no-cache --format json", 1
    ))
    assert risky.fetch("findings").any? { |finding|
      finding.fetch("path") == "app.py" &&
        finding.fetch("check_id") == "command_injection" &&
        finding.fetch("result") == "flagged"
    }
    (testpath/"safe.py").write <<~PYTHON
      import subprocess


      def ping(host):
          subprocess.run(["ping", "-c", "1", "--", host], check=True)
    PYTHON
    safe = JSON.parse(shell_output(
      "#{polaris_command} scan safe.py --root #{Shellwords.escape(testpath.to_s)} " \
      "--engine rules --model-source local --no-cache --format json", 0
    ))
    [risky, safe].each do |report|
      assert_equal "polaris.review/0.1.0", report.fetch("format")
      assert_equal "rules", report.fetch("model").fetch("engine")
      summary = report.fetch("summary")
      assert_equal 1, summary.fetch("files_reviewed")
      assert_equal({}, summary.fetch("files_skipped"))
      assert_equal 1, summary.fetch("units_total")
      assert_equal 1, summary.fetch("units_assessed")
      assert_equal 0, summary.fetch("results").fetch("error", 0)
    end
    assert_equal 1, risky.fetch("summary").fetch("results").fetch("flagged")
    assert_equal 0, safe.fetch("summary").fetch("results").fetch("flagged", 0)
    assert_operator safe.fetch("summary").fetch("results").fetch("ok"), :>, 0
  end
end

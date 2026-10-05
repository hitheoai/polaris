"""Portable self-test and model installation. Tiny random models exercise software only."""

import json
import tarfile

import pytest

pytest.importorskip("torch")
pytest.importorskip("transformers")

from ml_helpers import make_tiny_bundle, tiny_request  # noqa: E402

from polaris import selftest  # noqa: E402
from polaris.errors import PolarisRuntimeError  # noqa: E402
from polaris.install import InstallError, install_archive, list_models, pack  # noqa: E402
from polaris.review import Reviewer  # noqa: E402
from polaris.review.loader import resolve_model  # noqa: E402
from polaris.runtime import LocalBackend  # noqa: E402

pytestmark = pytest.mark.ml
CODE = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n"


@pytest.fixture
def sealed_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    bundle = make_tiny_bundle(tmp_path / "tiny")
    backend = LocalBackend(bundle, device="cpu", allow_experimental=True)
    requests = [tiny_request().model_dump(mode="json") | {"request_id": f"case-{i}"} for i in range(6)]
    test = selftest.create(backend, requests, margin=0.05)
    selftest.seal(bundle, test)
    return bundle


def test_a_different_runtime_is_accepted_only_after_the_self_test(sealed_bundle, monkeypatch):
    import polaris.runtime as runtime

    monkeypatch.setattr(runtime, "runtime_tag", lambda device: "other-os/other-chip/cpu/float32/sdpa")
    backend = LocalBackend(sealed_bundle, device="cpu", allow_experimental=True)
    assert backend.runtime_verified and backend.selftest_result["passed"] and not backend.selftest_result["cached"]
    assert backend.selftest_result["decision_changes"] == 0 and backend.identity.runtime_variant.startswith("other-os")
    report = Reviewer(backend).review_snippet(CODE)
    assert report.summary.results.get("error", 0) == 0 and report.summary.units_assessed == 1
    again = LocalBackend(sealed_bundle, device="cpu", allow_experimental=True)
    assert again.selftest_result["cached"] is True
    with pytest.raises(PolarisRuntimeError, match="experimental"):
        LocalBackend(sealed_bundle, device="cpu", allow_experimental=False)


def test_altered_reference_outputs_are_rejected(sealed_bundle, monkeypatch):
    import polaris.runtime as runtime

    test = selftest.load(sealed_bundle)
    altered = test.model_copy(update={"cases": [
        case.model_copy(update={"outputs": {k: [v[0] + 1.0, v[1]] for k, v in case.outputs.items()}})
        for case in test.cases
    ]})
    selftest.seal(sealed_bundle, altered)
    monkeypatch.setattr(runtime, "runtime_tag", lambda device: "another-machine/cpu/float32/sdpa")
    with pytest.raises(PolarisRuntimeError, match="calibration"):
        LocalBackend(sealed_bundle, device="cpu", allow_experimental=True)


def test_install_verifies_checksum_extracts_safely_and_activates(sealed_bundle, tmp_path):
    archive = tmp_path / "tiny-model.tar.gz"
    packed = pack(sealed_bundle, archive)
    assert (tmp_path / "tiny-model.tar.gz.sha256").read_text().startswith(packed["sha256"])
    with pytest.raises(InstallError, match="checksum mismatch"):
        install_archive(archive, sha256="0" * 64)
    result = install_archive(archive, device="cpu")
    assert result["active"] and result["loads"] and resolve_model().name == result["installed"].split("/")[-1]
    assert [m["active"] for m in list_models()] == [True]
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        info = tarfile.TarInfo("model/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(InstallError, match="links"):
        install_archive(evil, require_checksum=False)


def test_model_cli_info_list_and_selftest(sealed_bundle, tmp_path, capsys):
    from polaris.cli import main

    archive = tmp_path / "tiny.tar.gz"
    pack(sealed_bundle, archive)
    assert main(["model", "install", str(archive)]) == 0
    assert "installed and active" in capsys.readouterr().out
    assert main(["model", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["active"] is True
    assert main(["model", "selftest", "--device", "cpu"]) == 0
    assert "Ready on cpu" in capsys.readouterr().out
    assert main(["model", "info", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["self_test"] is True
    assert main(["model", "use", "does-not-exist"]) == 2

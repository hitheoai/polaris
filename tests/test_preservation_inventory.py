"""Synthetic preservation fixtures, including special files that must never be opened."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "preservation_inventory", Path(__file__).resolve().parents[1] / "scripts/inventory_preservation.py",
)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


def test_special_files_links_and_directories_are_not_followed_or_opened(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").write_bytes(b"original")
    (root / "empty").mkdir()
    (root / "outside").symlink_to(tmp_path)
    os.mkfifo(root / "fifo")
    listener = socket.socket(socket.AF_UNIX)
    monkeypatch.chdir(root)
    listener.bind("socket")
    original = os.open

    def guarded(path, *args, **kwargs):
        assert str(path) not in {"fifo", "socket", "outside"}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded)
    try:
        result = inventory.capture(root)
    finally:
        listener.close()
    entries = result["entries"]
    assert set(entries) == {".", "data", "empty", "outside", "fifo", "socket"}
    assert entries["fifo"]["kind"] == "fifo" and entries["socket"]["kind"] == "socket"
    assert entries["outside"]["target"] == str(tmp_path)
    assert entries["empty"]["kind"] == "directory"
    assert entries["data"]["bytes"] == 8
    assert "timestamps" in result["notCovered"]


@pytest.mark.parametrize("change,reason", [
    ("addition", "added"), ("removal", "removed"), ("type", "type_changed"),
    ("permissions", "changed"), ("bytes", "changed"),
])
def test_changes_are_visible(tmp_path, change, reason):
    path = tmp_path / "item"
    path.write_bytes(b"before")
    before = inventory.capture(tmp_path)
    if change == "addition":
        (tmp_path / "added").write_bytes(b"after")
    elif change == "removal":
        path.unlink()
    elif change == "type":
        path.unlink()
        os.mkfifo(path)
    elif change == "permissions":
        path.chmod(0o400)
    else:
        path.write_bytes(b"after")
    result = inventory.compare(before, inventory.capture(tmp_path))
    assert not result["preserved"]
    assert any(item["reason"] == reason for item in result["changes"])


def test_explicit_exclusions_new_output_and_scope(tmp_path):
    (tmp_path / "scratch").mkdir()
    (tmp_path / "scratch" / "changing").write_text("excluded")
    before = inventory.capture(tmp_path, exclude=["scratch"])
    (tmp_path / "scratch" / "changing").write_text("different")
    assert inventory.compare(before, inventory.capture(tmp_path, exclude=["scratch"]))["preserved"]
    with pytest.raises(ValueError):
        inventory.compare(before, inventory.capture(tmp_path))
    for bad in ("../outside", "/tmp", ".", "a/../b"):
        with pytest.raises(ValueError):
            inventory.capture(tmp_path, exclude=[bad])
    output = tmp_path / "receipt.json"
    inventory.write_new(output, before)
    with pytest.raises(FileExistsError):
        inventory.write_new(output, before)


def test_bounds_and_symlink_ancestor_are_refused(tmp_path):
    (tmp_path / "file").write_bytes(b"1234")
    for limits in (inventory.Limits(entries=1), inventory.Limits(file_bytes=3),
                   inventory.Limits(total_bytes=3), inventory.Limits(seconds=1e-12)):
        with pytest.raises(ValueError):
            inventory.capture(tmp_path, limits=limits)
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        inventory.capture(tmp_path / "link")


def test_file_replaced_between_stat_and_open_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "file"
    target.write_text("first")
    original = os.open

    def race(path, *args, **kwargs):
        if str(path) == "file":
            target.unlink()
            target.write_text("changed")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", race)
    with pytest.raises(ValueError, match="changed"):
        inventory.capture(tmp_path)


def test_directory_replaced_by_link_during_traversal_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "directory"
    target.mkdir()
    original = os.open

    def race(path, *args, **kwargs):
        if str(path) == "directory":
            target.rmdir()
            target.symlink_to(tmp_path, target_is_directory=True)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", race)
    with pytest.raises(OSError):
        inventory.capture(tmp_path)

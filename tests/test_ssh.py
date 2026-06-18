"""Tests for the SSH key writer."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from azkv_ssh_fetch.errors import SshKeyWriteError
from azkv_ssh_fetch.ssh import assert_safe_mode, write_private_key

SAMPLE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-base64-payload-here\n-----END OPENSSH PRIVATE KEY-----"


def test_write_private_key_sets_mode_0600(tmp_path: Path) -> None:
    dest = tmp_path / "ssh" / "id_test"
    written = write_private_key(SAMPLE_KEY, dest)

    assert written.exists()
    mode = stat.S_IMODE(written.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_write_private_key_appends_trailing_newline(tmp_path: Path) -> None:
    dest = tmp_path / "id_test"
    write_private_key(SAMPLE_KEY, dest)
    assert dest.read_text(encoding="utf-8").endswith("\n")


def test_write_private_key_preserves_existing_newline(tmp_path: Path) -> None:
    dest = tmp_path / "id_test"
    write_private_key(SAMPLE_KEY + "\n", dest)
    content = dest.read_text(encoding="utf-8")
    assert content.endswith("\n")
    assert not content.endswith("\n\n"), "should not double-newline"


def test_write_private_key_atomic_replace(tmp_path: Path) -> None:
    """A pre-existing key file should be replaced cleanly."""
    dest = tmp_path / "id_test"
    dest.write_text("OLD CONTENT\n", encoding="utf-8")
    os.chmod(dest, 0o600)

    write_private_key(SAMPLE_KEY, dest)
    assert "OLD CONTENT" not in dest.read_text(encoding="utf-8")
    assert SAMPLE_KEY in dest.read_text(encoding="utf-8")


def test_write_private_key_creates_missing_parent(tmp_path: Path) -> None:
    dest = tmp_path / "nested" / "deeply" / "id_test"
    write_private_key(SAMPLE_KEY, dest)
    assert dest.exists()
    # Parent should be 0700
    parent_mode = stat.S_IMODE(dest.parent.stat().st_mode)
    assert parent_mode == 0o700


def test_write_private_key_empty_raises(tmp_path: Path) -> None:
    with pytest.raises(SshKeyWriteError, match="empty"):
        write_private_key("", tmp_path / "id_test")


def test_assert_safe_mode_passes_for_0600(tmp_path: Path) -> None:
    p = tmp_path / "key"
    p.write_text("x", encoding="utf-8")
    p.chmod(0o600)
    assert_safe_mode(p)  # no exception


def test_assert_safe_mode_rejects_world_readable(tmp_path: Path) -> None:
    p = tmp_path / "key"
    p.write_text("x", encoding="utf-8")
    p.chmod(0o644)
    with pytest.raises(SshKeyWriteError, match="group/world"):
        assert_safe_mode(p)

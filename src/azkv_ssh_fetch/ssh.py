"""Local SSH key management: safe writes, mode 0600, atomic replace.

Avoids common footguns:
- Never write keys to world-readable temp dirs
- Always set mode 0600 BEFORE writing key material
- Use atomic os.replace so partial writes don't leave half-keys behind
- Append trailing newline if missing (OpenSSH cares)
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from azkv_ssh_fetch.errors import SshKeyWriteError

DEFAULT_SSH_DIR = Path.home() / ".ssh"
KEY_MODE = 0o600
DIR_MODE = 0o700


def default_ssh_dir() -> Path:
    """Return ~/.ssh, creating it with mode 0700 if missing."""
    DEFAULT_SSH_DIR.mkdir(mode=DIR_MODE, exist_ok=True)
    # Tighten perms even if it already existed with looser bits
    DEFAULT_SSH_DIR.chmod(DIR_MODE)
    return DEFAULT_SSH_DIR


def write_private_key(key_material: str, destination: Path) -> Path:
    """Write `key_material` to `destination` with mode 0600, atomically.

    Returns the resolved destination Path. Trailing newline is appended if missing.

    Raises:
        SshKeyWriteError: any IO problem (permissions, full disk, etc.).
    """
    if not key_material:
        raise SshKeyWriteError("empty key material; refusing to write")

    payload = key_material if key_material.endswith("\n") else key_material + "\n"

    dest = destination.expanduser().resolve()
    try:
        dest.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        # Tighten parent perms if it already existed
        dest.parent.chmod(DIR_MODE)
    except OSError as exc:
        raise SshKeyWriteError(f"cannot prepare {dest.parent}: {exc}") from exc

    # Write to a sibling tempfile with mode 0600, then atomic replace
    fd, tmp_path_str = tempfile.mkstemp(
        prefix=dest.name + ".",
        suffix=".tmp",
        dir=dest.parent,
    )
    tmp_path = Path(tmp_path_str)
    try:
        os.fchmod(fd, KEY_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp_path, dest)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        raise SshKeyWriteError(f"failed to write key to {dest}: {exc}") from exc

    # Belt-and-suspenders: enforce final mode in case umask interfered earlier
    dest.chmod(KEY_MODE)
    return dest


def assert_safe_mode(path: Path) -> None:
    """Raise if `path` is group/world readable (OpenSSH will reject)."""
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SshKeyWriteError(f"{path} is group/world accessible; chmod 600 required")

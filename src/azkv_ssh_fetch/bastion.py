"""Azure Bastion native-client invocation.

Shells out to the `az network bastion ssh` command rather than reimplementing the
RDP/SSH tunnel protocol. Requires `az` CLI >= 2.32 with the `ssh` extension.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from azkv_ssh_fetch.errors import BastionInvocationError


@dataclass(frozen=True)
class BastionTarget:
    """Connection coordinates for a Bastion-fronted VM/VMSS instance."""

    bastion_name: str
    bastion_resource_group: str
    target_resource_id: str
    """Full ARM resource ID of the target VM or VMSS instance."""
    username: str


def _require_az() -> str:
    """Return path to `az` or raise."""
    az = shutil.which("az")
    if az is None:
        raise BastionInvocationError(
            "the `az` CLI was not found on PATH; install from https://aka.ms/installazcli"
        )
    return az


def ssh_via_bastion(target: BastionTarget, private_key: Path) -> int:
    """Open an interactive SSH session through Azure Bastion.

    Blocks until the user exits. Returns the SSH exit code.

    Raises:
        BastionInvocationError: `az` is missing or the command exited with a
            non-SSH error (e.g., RBAC denial, unknown resource).
    """
    az = _require_az()
    cmd = [
        az,
        "network",
        "bastion",
        "ssh",
        "--name",
        target.bastion_name,
        "--resource-group",
        target.bastion_resource_group,
        "--target-resource-id",
        target.target_resource_id,
        "--auth-type",
        "ssh-key",
        "--username",
        target.username,
        "--ssh-key",
        str(private_key),
    ]
    try:
        completed = subprocess.run(cmd, check=False)  # noqa: S603 - args are controlled
    except OSError as exc:
        raise BastionInvocationError(f"failed to launch az: {exc}") from exc
    return completed.returncode

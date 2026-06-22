"""Integration tests for the `connect` subcommand.

These exercise the full fetch -> write -> bastion -> shred orchestration with
the Azure SDK and the Bastion subprocess mocked at their boundaries. The point
is to cover the lines that the unit-mock tests in test_cli.py skip: the
BastionTarget assembly, the exact argv passed to `az network bastion ssh`,
the on-disk state of the private key at the moment Bastion is invoked, and
the post-disconnect shred/keep behavior.

No real Azure or `az` CLI is touched.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from azkv_ssh_fetch.cli import app
from azkv_ssh_fetch.errors import BastionInvocationError

runner = CliRunner()

FAKE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakefakefake\n-----END OPENSSH PRIVATE KEY-----"
TARGET_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/rg-compute/providers/Microsoft.Compute/virtualMachines/web-01"
)


@pytest.fixture
def fake_ssh_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the connect command's SSH directory to a tmp path."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(mode=0o700)

    def _fake_default_ssh_dir() -> Path:
        ssh_dir.chmod(0o700)
        return ssh_dir

    monkeypatch.setattr("azkv_ssh_fetch.cli.default_ssh_dir", _fake_default_ssh_dir)
    return ssh_dir


@pytest.fixture
def stub_fetch(mocker: MockerFixture) -> None:
    """Mock fetch_secret to return canned fake key material."""
    mocker.patch("azkv_ssh_fetch.cli.fetch_secret", return_value=FAKE_KEY)


@pytest.fixture
def stub_az_on_path(mocker: MockerFixture) -> str:
    """Make `shutil.which('az')` return a fake path so _require_az passes."""
    az_path = "/usr/local/bin/az"
    mocker.patch("azkv_ssh_fetch.bastion.shutil.which", return_value=az_path)
    return az_path


def _argv_value(cmd: list[str], flag: str) -> str:
    """Return the value following `flag` in an argv list, raising if absent."""
    idx = cmd.index(flag)
    return cmd[idx + 1]


# ---------------------------------------------------------------------------
# Happy path: argv shape + key on disk at call time + default shred behavior
# ---------------------------------------------------------------------------


def test_connect_builds_correct_argv_and_writes_key_0600_then_shreds(
    fake_ssh_dir: Path,
    stub_fetch: None,
    stub_az_on_path: str,
    mocker: MockerFixture,
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(cmd: list[str], check: bool) -> subprocess.CompletedProcess[Any]:
        observed["cmd"] = cmd
        key_path = Path(_argv_value(cmd, "--ssh-key"))
        observed["key_existed"] = key_path.exists()
        observed["key_mode"] = stat.S_IMODE(key_path.stat().st_mode)
        observed["key_contents"] = key_path.read_text()
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    mocker.patch("azkv_ssh_fetch.bastion.subprocess.run", side_effect=fake_run)

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv-prod",
            "--secret",
            "web-01-key",
            "--bastion",
            "bastion-eus",
            "--bastion-rg",
            "rg-network",
            "--target-id",
            TARGET_ID,
            "--username",
            "azureuser",
        ],
    )

    assert result.exit_code == 0, result.stdout
    cmd = observed["cmd"]

    # az binary first, then the verb chain
    assert cmd[0] == stub_az_on_path
    assert cmd[1:4] == ["network", "bastion", "ssh"]

    # Every required flag carries the value we passed in
    assert _argv_value(cmd, "--name") == "bastion-eus"
    assert _argv_value(cmd, "--resource-group") == "rg-network"
    assert _argv_value(cmd, "--target-resource-id") == TARGET_ID
    assert _argv_value(cmd, "--auth-type") == "ssh-key"
    assert _argv_value(cmd, "--username") == "azureuser"

    # Key file lives at default_ssh_dir() / akf-<secret> and is on disk during the call
    key_path = Path(_argv_value(cmd, "--ssh-key"))
    assert key_path == fake_ssh_dir / "akf-web-01-key"
    assert observed["key_existed"] is True
    # CRITICAL: mode 0600 BEFORE Bastion ever sees the file
    assert observed["key_mode"] == 0o600
    # Content present (trailing newline added by write_private_key)
    assert FAKE_KEY in observed["key_contents"]

    # Default behavior is --shred-key: file is gone after disconnect
    assert not key_path.exists()
    assert "shredded" in result.stdout


def test_connect_username_defaults_to_azureuser(
    fake_ssh_dir: Path,
    stub_fetch: None,
    stub_az_on_path: str,
    mocker: MockerFixture,
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(cmd: list[str], check: bool) -> subprocess.CompletedProcess[Any]:
        observed["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    mocker.patch("azkv_ssh_fetch.bastion.subprocess.run", side_effect=fake_run)

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv",
            "--secret",
            "k",
            "--bastion",
            "b",
            "--bastion-rg",
            "r",
            "--target-id",
            TARGET_ID,
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert _argv_value(observed["cmd"], "--username") == "azureuser"


# ---------------------------------------------------------------------------
# --keep-key leaves the file behind
# ---------------------------------------------------------------------------


def test_connect_keep_key_leaves_file_on_disk(
    fake_ssh_dir: Path,
    stub_fetch: None,
    stub_az_on_path: str,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "azkv_ssh_fetch.bastion.subprocess.run",
        return_value=subprocess.CompletedProcess(args=[], returncode=0),
    )

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv",
            "--secret",
            "persist-key",
            "--bastion",
            "b",
            "--bastion-rg",
            "r",
            "--target-id",
            TARGET_ID,
            "--keep-key",
        ],
    )
    assert result.exit_code == 0, result.stdout

    persisted = fake_ssh_dir / "akf-persist-key"
    assert persisted.exists()
    assert stat.S_IMODE(persisted.stat().st_mode) == 0o600
    assert "shredded" not in result.stdout


# ---------------------------------------------------------------------------
# Bastion exit code propagates to CLI exit code, and key is still shredded
# ---------------------------------------------------------------------------


def test_connect_propagates_bastion_nonzero_exit_and_still_shreds(
    fake_ssh_dir: Path,
    stub_fetch: None,
    stub_az_on_path: str,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "azkv_ssh_fetch.bastion.subprocess.run",
        return_value=subprocess.CompletedProcess(args=[], returncode=130),
    )

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv",
            "--secret",
            "rc-key",
            "--bastion",
            "b",
            "--bastion-rg",
            "r",
            "--target-id",
            TARGET_ID,
        ],
    )
    # SSH session interrupted (130 = Ctrl+C) propagates through
    assert result.exit_code == 130
    # finally-block shred ran regardless
    assert not (fake_ssh_dir / "akf-rc-key").exists()


# ---------------------------------------------------------------------------
# az missing on PATH -> BastionInvocationError -> exit 2 -> key still shredded
# ---------------------------------------------------------------------------


def test_connect_missing_az_exits_2_and_shreds_key(
    fake_ssh_dir: Path,
    stub_fetch: None,
    mocker: MockerFixture,
) -> None:
    mocker.patch("azkv_ssh_fetch.bastion.shutil.which", return_value=None)
    spy_run = mocker.patch("azkv_ssh_fetch.bastion.subprocess.run")

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv",
            "--secret",
            "no-az",
            "--bastion",
            "b",
            "--bastion-rg",
            "r",
            "--target-id",
            TARGET_ID,
        ],
    )
    assert result.exit_code == 2
    # subprocess.run never invoked because _require_az raised first
    spy_run.assert_not_called()
    # Key was written but the finally-block shredded it on the error path
    assert not (fake_ssh_dir / "akf-no-az").exists()


# ---------------------------------------------------------------------------
# subprocess.run OSError (e.g., exec failure) is wrapped in BastionInvocationError
# ---------------------------------------------------------------------------


def test_connect_subprocess_oserror_surfaces_as_exit_2(
    fake_ssh_dir: Path,
    stub_fetch: None,
    stub_az_on_path: str,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "azkv_ssh_fetch.bastion.subprocess.run",
        side_effect=OSError("ENOEXEC: not an executable"),
    )

    result = runner.invoke(
        app,
        [
            "connect",
            "--vault",
            "kv",
            "--secret",
            "exec-fail",
            "--bastion",
            "b",
            "--bastion-rg",
            "r",
            "--target-id",
            TARGET_ID,
        ],
    )
    assert result.exit_code == 2
    # Error went to stderr (Console(stderr=True)) — exit code + cleanup are what matter
    assert not (fake_ssh_dir / "akf-exec-fail").exists()


# ---------------------------------------------------------------------------
# Direct unit coverage for ssh_via_bastion (covers bastion.py lines not hit
# via the CLI path, like the BastionInvocationError raise text).
# ---------------------------------------------------------------------------


def test_ssh_via_bastion_raises_when_az_missing(mocker: MockerFixture, tmp_path: Path) -> None:
    from azkv_ssh_fetch.bastion import BastionTarget, ssh_via_bastion

    mocker.patch("azkv_ssh_fetch.bastion.shutil.which", return_value=None)
    target = BastionTarget(
        bastion_name="b",
        bastion_resource_group="r",
        target_resource_id=TARGET_ID,
        username="u",
    )
    with pytest.raises(BastionInvocationError, match="`az` CLI was not found"):
        ssh_via_bastion(target, tmp_path / "key")


def test_ssh_via_bastion_wraps_oserror(mocker: MockerFixture, tmp_path: Path) -> None:
    from azkv_ssh_fetch.bastion import BastionTarget, ssh_via_bastion

    mocker.patch("azkv_ssh_fetch.bastion.shutil.which", return_value="/usr/local/bin/az")
    mocker.patch(
        "azkv_ssh_fetch.bastion.subprocess.run",
        side_effect=OSError("permission denied"),
    )
    target = BastionTarget(
        bastion_name="b",
        bastion_resource_group="r",
        target_resource_id=TARGET_ID,
        username="u",
    )
    with pytest.raises(BastionInvocationError, match="failed to launch az"):
        ssh_via_bastion(target, tmp_path / "key")

"""Tests for the CLI surface. Heavy mocking; no live Azure calls."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from azkv_ssh_fetch import __version__
from azkv_ssh_fetch.cli import app
from azkv_ssh_fetch.errors import KeyVaultAccessError, SecretNotFoundError
from azkv_ssh_fetch.keyvault import SecretSummary

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("list", "fetch", "connect"):
        assert cmd in result.stdout


def test_list_filters_to_ssh_shaped(mocker: MockerFixture) -> None:
    mocker.patch(
        "azkv_ssh_fetch.cli.list_secrets",
        return_value=iter(
            [
                SecretSummary(name="alpha-ssh", enabled=True, content_type=None),
                SecretSummary(name="db-password", enabled=True, content_type=None),
                SecretSummary(name="id_rsa-prod", enabled=True, content_type=None),
                SecretSummary(name="disabled-ssh", enabled=False, content_type=None),
            ]
        ),
    )
    result = runner.invoke(app, ["list", "--vault", "kv-test"])
    assert result.exit_code == 0
    assert "alpha-ssh" in result.stdout
    assert "id_rsa-prod" in result.stdout
    assert "db-password" not in result.stdout
    assert "disabled-ssh" not in result.stdout


def test_list_empty_exits_1(mocker: MockerFixture) -> None:
    mocker.patch("azkv_ssh_fetch.cli.list_secrets", return_value=iter([]))
    result = runner.invoke(app, ["list", "--vault", "kv-test"])
    assert result.exit_code == 1


def test_list_kv_error_exits_2(mocker: MockerFixture) -> None:
    mocker.patch(
        "azkv_ssh_fetch.cli.list_secrets",
        side_effect=KeyVaultAccessError("nope"),
    )
    result = runner.invoke(app, ["list", "--vault", "kv-test"])
    assert result.exit_code == 2


def test_fetch_writes_to_output(tmp_path: Path, mocker: MockerFixture) -> None:
    mocker.patch(
        "azkv_ssh_fetch.cli.fetch_secret",
        return_value="-----BEGIN OPENSSH PRIVATE KEY-----\ncontent\n-----END OPENSSH PRIVATE KEY-----",
    )
    out = tmp_path / "id_test"
    result = runner.invoke(app, ["fetch", "--vault", "kv-test", "my-secret", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    import stat

    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_fetch_missing_secret_exits_2(tmp_path: Path, mocker: MockerFixture) -> None:
    mocker.patch(
        "azkv_ssh_fetch.cli.fetch_secret",
        side_effect=SecretNotFoundError("nope"),
    )
    result = runner.invoke(
        app,
        ["fetch", "--vault", "kv-test", "ghost", "--output", str(tmp_path / "k")],
    )
    assert result.exit_code == 2


def test_vault_from_env(monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture) -> None:
    monkeypatch.setenv("AZKV_VAULT", "kv-from-env")
    captured: dict[str, str] = {}

    def fake_list(vault: str):
        captured["vault"] = vault
        return iter([SecretSummary(name="x-ssh", enabled=True, content_type=None)])

    mocker.patch("azkv_ssh_fetch.cli.list_secrets", side_effect=fake_list)
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert captured["vault"] == "kv-from-env"

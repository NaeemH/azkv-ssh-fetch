"""Tests for the Key Vault wrapper. SDK is mocked."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from pytest_mock import MockerFixture

from azkv_ssh_fetch import keyvault
from azkv_ssh_fetch.errors import KeyVaultAccessError, SecretNotFoundError


def _patch_client(mocker: MockerFixture) -> MagicMock:
    """Patch the SecretClient factory and return the mock client."""
    client = MagicMock()
    mocker.patch.object(keyvault, "_client", return_value=client)
    return client


def test_fetch_secret_returns_value(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    secret = MagicMock()
    secret.value = "PRIVATE-KEY-CONTENT"
    client.get_secret.return_value = secret

    value = keyvault.fetch_secret("kv-test", "my-key")
    assert value == "PRIVATE-KEY-CONTENT"
    client.get_secret.assert_called_once_with("my-key")


def test_fetch_secret_missing_raises(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    client.get_secret.side_effect = ResourceNotFoundError(message="not found")

    with pytest.raises(SecretNotFoundError, match="not found"):
        keyvault.fetch_secret("kv-test", "missing")


def test_fetch_secret_http_error_raises_access(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    client.get_secret.side_effect = HttpResponseError(message="forbidden")

    with pytest.raises(KeyVaultAccessError, match="forbidden"):
        keyvault.fetch_secret("kv-test", "any")


def test_fetch_secret_null_value_raises(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    secret = MagicMock()
    secret.value = None
    client.get_secret.return_value = secret

    with pytest.raises(SecretNotFoundError, match="no value"):
        keyvault.fetch_secret("kv-test", "blank")


def test_list_secrets_yields_summaries(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    p1 = MagicMock(name="prop1")
    p1.name = "alpha-ssh"
    p1.enabled = True
    p1.content_type = "application/x-pem-file"
    p2 = MagicMock(name="prop2")
    p2.name = "beta"
    p2.enabled = False
    p2.content_type = None
    client.list_properties_of_secrets.return_value = iter([p1, p2])

    out = list(keyvault.list_secrets("kv-test"))
    assert [s.name for s in out] == ["alpha-ssh", "beta"]
    assert out[0].enabled is True
    assert out[0].content_type == "application/x-pem-file"
    assert out[1].enabled is False


def test_list_secrets_http_error(mocker: MockerFixture) -> None:
    client = _patch_client(mocker)
    client.list_properties_of_secrets.side_effect = HttpResponseError(message="denied")

    with pytest.raises(KeyVaultAccessError, match="denied"):
        list(keyvault.list_secrets("kv-test"))

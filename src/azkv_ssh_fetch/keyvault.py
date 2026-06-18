"""Azure Key Vault interactions.

Thin wrapper around `azure-keyvault-secrets` + `azure-identity`. Centralizes auth
and provides typed return values so the CLI layer stays free of SDK boilerplate.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from azkv_ssh_fetch.errors import KeyVaultAccessError, SecretNotFoundError


@dataclass(frozen=True)
class SecretSummary:
    """Lightweight view of a Key Vault secret (no value)."""

    name: str
    enabled: bool
    content_type: str | None


def _client(vault_name: str) -> SecretClient:
    """Build a SecretClient for `vault_name` using DefaultAzureCredential.

    Auth precedence (azure-identity defaults): env vars, managed identity, az CLI,
    VS Code, Azure PowerShell, interactive browser. The CLI relies on `az login`
    in practice.
    """
    url = f"https://{vault_name}.vault.azure.net"
    return SecretClient(vault_url=url, credential=DefaultAzureCredential())


def list_secrets(vault_name: str) -> Iterator[SecretSummary]:
    """Yield all enabled secrets in the vault.

    Raises:
        KeyVaultAccessError: caller lacks `list` permission or vault is unreachable.
    """
    client = _client(vault_name)
    try:
        for prop in client.list_properties_of_secrets():
            yield SecretSummary(
                name=prop.name or "",
                enabled=bool(prop.enabled),
                content_type=prop.content_type,
            )
    except HttpResponseError as exc:
        raise KeyVaultAccessError(f"cannot list secrets in {vault_name!r}: {exc.message}") from exc


def fetch_secret(vault_name: str, secret_name: str) -> str:
    """Fetch the value of `secret_name` from `vault_name`.

    Raises:
        SecretNotFoundError: the secret does not exist (or caller cannot see it).
        KeyVaultAccessError: any other access failure.
    """
    client = _client(vault_name)
    try:
        secret = client.get_secret(secret_name)
    except ResourceNotFoundError as exc:
        raise SecretNotFoundError(
            f"secret {secret_name!r} not found in vault {vault_name!r}"
        ) from exc
    except HttpResponseError as exc:
        raise KeyVaultAccessError(
            f"cannot fetch {secret_name!r} from {vault_name!r}: {exc.message}"
        ) from exc

    if secret.value is None:
        raise SecretNotFoundError(f"secret {secret_name!r} has no value")
    return secret.value

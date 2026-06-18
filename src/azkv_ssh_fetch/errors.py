"""Typed errors raised by the package."""

from __future__ import annotations


class AzkvSshFetchError(Exception):
    """Base class for all package errors."""


class KeyVaultAccessError(AzkvSshFetchError):
    """Raised when Key Vault is unreachable or caller lacks permission."""


class SecretNotFoundError(AzkvSshFetchError):
    """Raised when the named secret does not exist in the vault."""


class SshKeyWriteError(AzkvSshFetchError):
    """Raised when the SSH key cannot be written to disk safely."""


class BastionInvocationError(AzkvSshFetchError):
    """Raised when `az network bastion` invocation fails."""

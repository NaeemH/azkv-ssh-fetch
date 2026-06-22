"""VCR-replay tests against the Key Vault SDK layer.

These tests exercise the *real* `azure-keyvault-secrets` + `azure-identity` code
paths -- HTTP requests included -- but replay against cassettes recorded once
against a personal Azure subscription. CI never touches the network.

Recording workflow (operator only)::

    az login
    export AZURE_TENANT_ID=<your-tenant>
    export AZURE_SUBSCRIPTION_ID=<your-personal-sub>
    export AZKV_TEST_RECORD_VAULT=<your-personal-vault-name>
    pytest --record-mode=once tests/test_keyvault_vcr.py

Then inspect tests/cassettes/test_keyvault_vcr/*.yaml and confirm:

* No real GUIDs (only 00000000-0000-0000-0000-000000000000)
* No real vault names (only "test-vault")
* Every Authorization header reads "REDACTED"
* Every secret "value" field reads "REDACTED"

Only then commit the cassettes. The scrubbers in conftest.py are defense-
in-depth; the human eyeball is the actual safety mechanism.
"""

from __future__ import annotations

import pytest

from azkv_ssh_fetch import keyvault
from tests.conftest import SCRUBBED_VAULT, skip_if_no_cassette

VAULT = SCRUBBED_VAULT  # cassettes were recorded with this rewritten name


@pytest.mark.vcr
@skip_if_no_cassette("test_keyvault_vcr", "test_list_secrets_replays_recorded_call")
def test_list_secrets_replays_recorded_call() -> None:
    secrets = list(keyvault.list_secrets(VAULT))
    # The recorded vault is expected to have at least one secret; the assertion
    # is intentionally loose so re-recording against a different vault still
    # passes as long as the cassette captured a non-empty list.
    assert secrets, "expected the recorded cassette to contain at least one secret"
    for s in secrets:
        assert s.name, "secret entries must have a name"


@pytest.mark.vcr
@skip_if_no_cassette("test_keyvault_vcr", "test_fetch_secret_replays_recorded_call")
def test_fetch_secret_replays_recorded_call() -> None:
    # The cassette must be recorded against a secret named "akf-test-key" in
    # the personal vault. Its real value is redacted to "REDACTED" by the
    # scrubber; the SDK returns whatever string we left in the cassette.
    value = keyvault.fetch_secret(VAULT, "akf-test-key")
    assert value, "fetched secret should be a non-empty string (REDACTED in cassette)"
